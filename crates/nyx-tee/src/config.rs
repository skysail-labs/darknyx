//! Env-driven config. The full set of allowed env vars must also
//! appear in `app-compose.json::allowed_envs` — changing this list
//! changes `compose_hash` and therefore requires a new image
//! authorization in dstack governance + a multisig rotation of
//! `vault_config.tee_pubkey` on Solana. See
//! `docs/tee-architecture.md` §11.

use anyhow::{bail, Result};

use crate::api::auth::{TEST_API_KEY, TEST_API_SECRET, TEST_PASSPHRASE};

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

    /// Explicitly permit the test-only auth/state fallback when the configured
    /// dstack simulator cannot be reached. This is accepted only when
    /// `DSTACK_SIMULATOR_ENDPOINT` is also set, so a production CVM can never
    /// fall through to `ApiState::for_tests()` after a dstack/KMS failure.
    /// `NYX_TEE_ALLOW_TEST_AUTH`, default false.
    pub allow_test_auth: bool,

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
    /// Protocol fee rate in basis points. `NYX_TEE_FEE_RATE_BPS`,
    /// default 30 (0.3%). The matcher charges `amount × bps / 10_000`
    /// on each leg (seller→base bucket, buyer→quote bucket) and mints a
    /// fee note per non-empty bucket. 0 disables fees entirely (no fee
    /// notes). Should mirror the on-chain `VaultConfig.fee_rate_bps`
    /// (≤ 10_000, enforced by set_protocol_config) so the matcher's
    /// charge matches what settlement conservation expects. On a real
    /// boot the TEE reads the authoritative on-chain rate and OVERRIDES
    /// this env value (see `main.rs::read_on_chain_vault_config`), since
    /// the batched-settle handler enforces a fee FLOOR against it — so
    /// this acts only as a fallback (explicit simulator mode / config absent).
    pub fee_rate_bps: u64,
    /// Owner commitment the protocol fee notes are minted to (32 bytes).
    /// `NYX_TEE_PROTOCOL_OWNER_COMMITMENT` (hex), default `[0;32]`. Set
    /// it to the on-chain protocol owner commitment (e2e-config
    /// `protocol.ownerCommitmentHex`) so the collected fee notes are
    /// spendable by the protocol via the normal VALID_SPEND path; left
    /// at zero the fee notes still mint + append but are unclaimable.
    /// MUST be BN254-Fr-safe (it's a Poseidon-output commitment).
    pub protocol_owner_commitment: [u8; 32],
    /// Max settle Tx D's the settle worker sends CONCURRENTLY within a batch.
    /// `NYX_TEE_SETTLE_SEND_CONCURRENCY`, default 16. Concurrent sends let the
    /// leader co-include settles in one block so they confirm together (the
    /// on-chain throughput lever); 1 reproduces the old one-at-a-time behavior.
    pub settle_send_concurrency: u64,
    /// Number of Merkle-tree shards (`= vault_config.num_trees`). The settle
    /// worker derives K signer keys (`nyx/ed25519-signer/v1/{i}`) and
    /// round-robins each match across `(key[j], merkle_tree[j])` so the
    /// concurrent settle Tx D's share no writable account → the leader can
    /// co-include + parallelize them. `NYX_TEE_NUM_TREES`, default 1 (single
    /// shard = the pre-sharding behavior). MUST equal the on-chain
    /// `num_trees` set at `initialize`. Range 1..=16.
    pub num_trees: u8,
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

// ── env parsing ──────────────────────────────────────────────────────
//
// Compose interpolates `${VAR}` to an EMPTY STRING when the value isn't
// supplied at deploy, so every helper treats `""` (after trim) the same
// as unset → the default. A NON-EMPTY but malformed value is a hard
// error (propagated by `from_env`), so a config typo fails startup
// loudly instead of silently falling back to a dev placeholder.

/// A string env var, trimmed; unset or empty → `default`.
fn env_string_or(var: &str, default: &str) -> String {
    match std::env::var(var) {
        Ok(s) if !s.trim().is_empty() => s.trim().to_string(),
        _ => default.to_string(),
    }
}

/// Parse a 32-byte mint from a base58 env var. Unset/empty → `default`;
/// non-empty malformed → `Err`.
fn parse_mint_env(var: &str, default: [u8; 32]) -> Result<[u8; 32]> {
    let Ok(s) = std::env::var(var) else {
        return Ok(default);
    };
    let s = s.trim();
    if s.is_empty() {
        return Ok(default);
    }
    match bs58::decode(s).into_vec() {
        Ok(b) if b.len() == 32 => {
            let mut m = [0u8; 32];
            m.copy_from_slice(&b);
            Ok(m)
        }
        _ => Err(anyhow::anyhow!("{var}: invalid mint (need 32-byte base58)")),
    }
}

/// Parse a 32-byte hex value (optional `0x` prefix) from an env var —
/// for commitments (raw field elements, not base58). Unset/empty →
/// `default`; non-empty malformed → `Err`.
fn parse_hex32_env(var: &str, default: [u8; 32]) -> Result<[u8; 32]> {
    let Ok(s) = std::env::var(var) else {
        return Ok(default);
    };
    let t = s.trim();
    let t = t.strip_prefix("0x").unwrap_or(t);
    if t.is_empty() {
        return Ok(default);
    }
    match hex::decode(t) {
        Ok(b) if b.len() == 32 => {
            let mut k = [0u8; 32];
            k.copy_from_slice(&b);
            // This value is Poseidon-hashed downstream (it's a commitment /
            // field element — e.g. the fee-note owner), so it MUST be a
            // canonical BN254 `Fr` (< the modulus). A 32-byte value that's
            // ≥ the modulus passes the length check but blows up at runtime
            // (PoseidonFailed) when the matcher mints a fee note. Fail fast
            // here. `fr_from_be_bytes` rejects non-canonical values.
            darkpool_crypto::fr_from_be_bytes(&k).map_err(|_| {
                anyhow::anyhow!(
                    "{var}: not a canonical BN254 field element (must be < the Fr modulus)"
                )
            })?;
            Ok(k)
        }
        _ => Err(anyhow::anyhow!(
            "{var}: invalid hex (need 32-byte / 64 hex chars)"
        )),
    }
}

/// Parse an OPTIONAL 32-byte pubkey (base58) from an env var.
/// Unset/empty → `None`; non-empty malformed → `Err`.
fn parse_pubkey_env(var: &str) -> Result<Option<[u8; 32]>> {
    let Ok(s) = std::env::var(var) else {
        return Ok(None);
    };
    let s = s.trim();
    if s.is_empty() {
        return Ok(None);
    }
    match bs58::decode(s).into_vec() {
        Ok(b) if b.len() == 32 => {
            let mut k = [0u8; 32];
            k.copy_from_slice(&b);
            Ok(Some(k))
        }
        _ => Err(anyhow::anyhow!(
            "{var}: invalid pubkey (need 32-byte base58)"
        )),
    }
}

/// Parse a `u64` env var. Unset/empty → `default`; non-empty
/// unparseable → `Err`.
fn parse_u64_env(var: &str, default: u64) -> Result<u64> {
    let Ok(s) = std::env::var(var) else {
        return Ok(default);
    };
    let s = s.trim();
    if s.is_empty() {
        return Ok(default);
    }
    s.parse::<u64>()
        .map_err(|e| anyhow::anyhow!("{var}: invalid u64 ({e})"))
}

/// Parse a strict boolean env var. Empty/unset uses `default`; accepted values
/// are `1`/`true` and `0`/`false` (case-insensitive).
fn parse_bool_env(var: &str, default: bool) -> Result<bool> {
    let Ok(s) = std::env::var(var) else {
        return Ok(default);
    };
    parse_bool_value(var, &s, default)
}

fn parse_bool_value(var: &str, value: &str, default: bool) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" => Ok(default),
        "1" | "true" => Ok(true),
        "0" | "false" => Ok(false),
        _ => bail!("{var}: invalid boolean (use 1/true or 0/false)"),
    }
}

fn env_nonempty(var: &str) -> Option<String> {
    std::env::var(var)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn is_known_test_credential(var: &str, value: &str) -> bool {
    matches!(
        (var, value),
        ("NYX_TEE_API_KEY", TEST_API_KEY)
            | ("NYX_TEE_API_SECRET", TEST_API_SECRET)
            | ("NYX_TEE_PASSPHRASE", TEST_PASSPHRASE)
    )
}

/// Enforce the boundary between explicit local simulator fixtures and a real
/// CVM boot. Known public test credentials are never accepted outside that
/// simulator mode.
fn validate_auth_mode(dstack_socket: Option<&str>, allow_test_auth: bool) -> Result<()> {
    if allow_test_auth && dstack_socket.is_none() {
        bail!("NYX_TEE_ALLOW_TEST_AUTH is permitted only with DSTACK_SIMULATOR_ENDPOINT");
    }

    if !allow_test_auth {
        for var in [
            "NYX_TEE_API_KEY",
            "NYX_TEE_API_SECRET",
            "NYX_TEE_PASSPHRASE",
        ] {
            if env_nonempty(var)
                .as_deref()
                .is_some_and(|value| is_known_test_credential(var, value))
            {
                bail!("{var} uses a known public test credential; production startup refused");
            }
        }
    }

    Ok(())
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

        let dstack_socket = std::env::var("DSTACK_SIMULATOR_ENDPOINT")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let allow_test_auth = parse_bool_env("NYX_TEE_ALLOW_TEST_AUTH", false)?;
        validate_auth_mode(dstack_socket.as_deref(), allow_test_auth)?;

        Ok(Self {
            http_bind: env_string_or("NYX_TEE_HTTP_BIND", "0.0.0.0:8080"),
            // Empty (compose `${VAR}` with no value) → the default, NOT a
            // literal empty URL that breaks every RPC call.
            solana_rpc_url: env_string_or(
                "NYX_TEE_SOLANA_RPC_URL",
                "https://api.devnet.solana.com",
            ),
            dstack_socket,
            allow_test_auth,
            feed_ids,
            sync_from_slot: parse_u64_env("NYX_TEE_SYNC_FROM_SLOT", 0)?,
            base_mint: parse_mint_env("NYX_TEE_BASE_MINT", default_base_mint())?,
            quote_mint: parse_mint_env("NYX_TEE_QUOTE_MINT", default_quote_mint())?,
            tick_size: parse_u64_env("NYX_TEE_TICK_SIZE", 1)?,
            min_order_size: parse_u64_env("NYX_TEE_MIN_ORDER_SIZE", 0)?,
            settle_lookup_table: parse_pubkey_env("NYX_TEE_SETTLE_LOOKUP_TABLE")?,
            // Clamp to 100% — the matcher's fee math assumes
            // bps ≤ 10_000 (normally enforced on-chain by
            // set_protocol_config; the CVM matcher isn't gated by it).
            fee_rate_bps: parse_u64_env("NYX_TEE_FEE_RATE_BPS", 30)?.min(10_000),
            protocol_owner_commitment: parse_hex32_env(
                "NYX_TEE_PROTOCOL_OWNER_COMMITMENT",
                [0u8; 32],
            )?,
            settle_send_concurrency: parse_u64_env("NYX_TEE_SETTLE_SEND_CONCURRENCY", 16)?.max(1),
            // 1..=16 (vault MAX_TREES). Clamp rather than fail: a 0 or absurd
            // value falls back to a single shard (the safe, pre-sharding path).
            num_trees: parse_u64_env("NYX_TEE_NUM_TREES", 1)?.clamp(1, 16) as u8,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_requires_an_explicit_simulator_endpoint() {
        let err = validate_auth_mode(None, true).unwrap_err();
        assert!(err.to_string().contains("DSTACK_SIMULATOR_ENDPOINT"));
        validate_auth_mode(Some("/tmp/dstack.sock"), true).unwrap();
    }

    #[test]
    fn strict_bool_parser_rejects_ambiguous_values() {
        assert!(parse_bool_value("FLAG", "1", false).unwrap());
        assert!(parse_bool_value("FLAG", "TRUE", false).unwrap());
        assert!(!parse_bool_value("FLAG", "0", true).unwrap());
        assert!(!parse_bool_value("FLAG", "false", true).unwrap());
        assert!(parse_bool_value("FLAG", "", true).unwrap());
        assert!(parse_bool_value("FLAG", "yes", false).is_err());
    }

    #[test]
    fn public_test_credentials_are_recognised_by_field() {
        assert!(is_known_test_credential("NYX_TEE_API_KEY", TEST_API_KEY));
        assert!(is_known_test_credential(
            "NYX_TEE_API_SECRET",
            TEST_API_SECRET
        ));
        assert!(is_known_test_credential(
            "NYX_TEE_PASSPHRASE",
            TEST_PASSPHRASE
        ));
        assert!(!is_known_test_credential(
            "NYX_TEE_API_KEY",
            "fresh-production-key"
        ));
    }
}
