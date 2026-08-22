//! Env-driven config. The full set of allowed env vars must also
//! appear in `app-compose.json::allowed_envs` — changing this list
//! changes `compose_hash` and therefore requires a new image
//! authorization in dstack governance and a multisig rotation of the
//! `vault_config.tee_pubkeys` set on Solana. Under tree sharding that set
//! holds all K shard signers, and they must be registered in shard order —
//! `keys[j]` settles shard `j`. See `docs/tee-architecture.md` §11.
//!
//! Most malformed values fail startup rather than falling back, and an EMPTY
//! value falls back to the default. That asymmetry is deliberate, but it means a
//! variable silently reverting to its default is indistinguishable from one that
//! was never set.
//!
//! The fail-closed rule is not universal, so do not rely on it as an invariant:
//! a non-UTF-8 value reads as unset, some out-of-range numerics are clamped
//! rather than rejected, and `DARKNYX_TEE_SOLANA_RPC_URL` is not validated at
//! load time — a malformed URL surfaces later as an RPC failure.

use std::collections::HashSet;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::api::auth::{TEST_API_KEY, TEST_API_SECRET, TEST_PASSPHRASE};
use crate::oracle::hermes::UPGRADED_HERMES_ENDPOINT;
use crate::oracle::OracleMode;

pub const MAX_MARKETS_PER_CVM: usize = 16;

#[derive(Clone, Eq, PartialEq)]
pub struct SecretString(String);

impl SecretString {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

/// One independently routed order book inside the CVM. Market economics are
/// replaced from the finalized on-chain `MarketConfig` at governed boot; this
/// only identifies the pair, API symbol, and oracle feed to fetch.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MarketSpec {
    pub symbol: String,
    pub base_mint: [u8; 32],
    pub quote_mint: [u8; 32],
    pub oracle_feed_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MarketSpecJson {
    symbol: String,
    base_mint: String,
    quote_mint: String,
    oracle_feed_id: String,
}

/// Which transport `darknyx-tee` serves (T-03P).
///
/// Deliberately an explicit enum rather than a bool: a client reading `/info`
/// must be able to tell the legacy gateway-terminated path apart *by name*,
/// not infer it from a missing field. Production release assembly rejects
/// `GatewayTerminated`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportModeConfig {
    /// TLS terminated by the dstack gateway. The legacy path.
    GatewayTerminated,
    /// TLS terminated inside this enclave with a boot-random, quote-bound key.
    RaTls,
}

impl TransportModeConfig {
    /// Wire/env spelling. Matches the `transport_mode` value on
    /// `/transport-attestation`, so one vocabulary covers config and API.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GatewayTerminated => "gateway-terminated",
            Self::RaTls => "ra-tls",
        }
    }

    /// Parse `DARKNYX_TEE_TRANSPORT_MODE`.
    ///
    /// Unset or empty means the legacy default. A **set but unrecognised**
    /// value is a hard error rather than a silent fallback: a typo like
    /// `ratls` must not quietly leave the operator on the weaker transport
    /// believing they enabled the stronger one.
    pub fn from_env() -> anyhow::Result<Self> {
        let raw = match std::env::var("DARKNYX_TEE_TRANSPORT_MODE") {
            Err(std::env::VarError::NotPresent) => return Ok(Self::GatewayTerminated),
            // NOT `Err(_)`. `VarError::NotUnicode` means the variable IS set —
            // the operator asked for something — and lumping it in with "unset"
            // silently selects the weaker transport for a value that was
            // probably meant to be `ra-tls`. That is the exact fail-open this
            // function's doc comment promises not to do for a typo, and a
            // non-UTF-8 value deserves the same treatment as an unrecognised
            // one.
            Err(e @ std::env::VarError::NotUnicode(_)) => anyhow::bail!(
                "DARKNYX_TEE_TRANSPORT_MODE is set but not valid UTF-8 ({e}); \
                 expected \"ra-tls\" or \"gateway-terminated\". Refusing to start \
                 rather than silently falling back to the legacy transport."
            ),
            Ok(v) => v,
        };
        let v = raw.trim();
        if v.is_empty() {
            return Ok(Self::GatewayTerminated);
        }
        match v {
            "gateway-terminated" => Ok(Self::GatewayTerminated),
            "ra-tls" => Ok(Self::RaTls),
            other => anyhow::bail!(
                "DARKNYX_TEE_TRANSPORT_MODE={other:?} is not recognised; expected \
                 \"ra-tls\" or \"gateway-terminated\". Refusing to start rather than \
                 silently falling back to the legacy transport."
            ),
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)] // Not every field is read on every build profile.
pub struct Config {
    /// Boot-static market routing table. `DARKNYX_TEE_MARKETS_JSON` is the
    /// preferred governed multi-market input. The legacy singular envs are
    /// parsed into a one-entry table for devnet/loadgen compatibility.
    pub markets: Vec<MarketSpec>,
    /// HTTP listen address. Defaults to 0.0.0.0:8080 inside the
    /// CVM; dstack-ingress fronts this on :443.
    pub http_bind: String,
    /// Which transport this instance serves (T-03P).
    ///
    /// `ra-tls` terminates TLS inside the enclave with a boot-random key whose
    /// SPKI is quote-bound, reached through the dstack gateway's `s`-suffix
    /// passthrough route. `gateway-terminated` is the legacy path where the
    /// dstack gateway terminates TLS — retained for migration and local
    /// development, and explicitly reported on `/info` so a client can tell
    /// which one it is talking to rather than inferring it from absence.
    ///
    /// Defaults to `gateway-terminated`: turning RA-TLS on is a deployment
    /// decision, and defaulting to the stronger mode would break every existing
    /// devnet deployment on upgrade.
    pub transport_mode: TransportModeConfig,
    /// TLS listen address used when `transport_mode` is `ra-tls`. Separate from
    /// `http_bind` so the plaintext listener can stay bound to the CVM-internal
    /// interface during migration while TLS faces the gateway.
    pub tls_bind: String,

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
    /// `DARKNYX_TEE_ALLOW_TEST_AUTH`, default false.
    pub allow_test_auth: bool,

    /// Comma-separated list of Pyth Hermes feed ids the oracle
    /// sync task should refresh on every tick. Empty by default —
    /// dev-machine boots without network access skip oracle sync
    /// entirely and the matcher's tick simply no-ops (stale oracle
    /// is treated as "skip cycle"). Production sets one feed per
    /// market via `DARKNYX_TEE_MARKETS_JSON`; the singular compatibility path
    /// uses `DARKNYX_TEE_FEED_IDS`. Each entry is a 64-char-hex Pyth feed id.
    pub feed_ids: Vec<String>,
    /// Exactly one versioned oracle producer. Development defaults to finalized
    /// upgraded Pyth Core push accounts; mainnet policy explicitly selects the
    /// licensed low-latency router mode.
    pub oracle_mode: OracleMode,
    /// Hermes base URL. Used only by `pyth-router-quorum-v1` and defaulted to
    /// the authenticated upgraded service. There is no legacy endpoint path.
    pub hermes_endpoint: String,
    /// Bearer credential supplied only through encrypted deployment env. Its
    /// `Debug` implementation is redacted.
    pub pyth_api_key: Option<SecretString>,

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
    /// openings against this. From `DARKNYX_TEE_BASE_MINT` (base58); defaults
    /// to a deterministic placeholder so dev/loadgen behaviour is
    /// unchanged when unset. For a REAL settle it MUST equal the on-chain
    /// mint the deposited notes use (else intake rejects the opening on a
    /// mint mismatch).
    pub base_mint: [u8; 32],
    /// Market quote mint (32 bytes). BID-side openings verify against
    /// this. From `DARKNYX_TEE_QUOTE_MINT` (base58).
    pub quote_mint: [u8; 32],
    /// `true` when strict multi-market JSON is present or both singular market
    /// mint env vars were supplied. This selects governed real settlement.
    pub governed_market: bool,
    /// Canonical API/order symbol for the configured mint pair.
    /// `DARKNYX_TEE_MARKET_SYMBOL`, default `SOL-USDC`.
    pub market_symbol: String,
    /// Price tick. `DARKNYX_TEE_TICK_SIZE`, default 1.
    pub tick_size: u64,
    /// Minimum order size. `DARKNYX_TEE_MIN_ORDER_SIZE`, default 0.
    pub min_order_size: u64,
    /// On-chain address of the STATIC settle ALT (the one devnet-setup
    /// creates holding `vault_config`, `instructions_sysvar`,
    /// `system_program` — see SDK `static_alt_addresses()`). From
    /// `DARKNYX_TEE_SETTLE_LOOKUP_TABLE` (base58). When set, the settle
    /// worker stacks it UNDER the per-batch ALT so the v0 settle tx
    /// stays under Solana's 1232-byte cap; without it the tx is ~93 B
    /// larger and overflows on the real-mint settle path. Unset → the
    /// worker uses only the per-batch ALT (fine for the smaller test
    /// payloads, NOT for a real settle).
    pub settle_lookup_table: Option<[u8; 32]>,
    /// Protocol fee rate in basis points. `DARKNYX_TEE_FEE_RATE_BPS`,
    /// default 30 (0.3%). The matcher charges `amount × bps / 10_000`
    /// on each leg (seller→base bucket, buyer→quote bucket) and mints a
    /// fee note per non-empty bucket. 0 disables fees entirely (no fee
    /// notes). Should mirror the on-chain `VaultConfig.fee_rate_bps`
    /// (≤ 10_000, enforced by set_protocol_config) so the matcher's
    /// charge matches what settlement conservation expects. On a real
    /// boot the TEE reads the authoritative on-chain rate and OVERRIDES
    /// this env value (see `main.rs::read_governance_snapshot`), since the
    /// proof enforces the exact governed fee. This value is used only in
    /// explicit simulator / placeholder-loadgen mode.
    pub fee_rate_bps: u64,
    /// Simulator/placeholder-loadgen owner commitment (32-byte hex), from
    /// `DARKNYX_TEE_PROTOCOL_OWNER_COMMITMENT`; default `[0;32]`. Governed
    /// real-market boot adopts the finalized `VaultConfig` value instead and
    /// rejects a zero owner when fees are enabled. MUST be BN254-Fr-safe (it is
    /// a Poseidon-output commitment).
    pub protocol_owner_commitment: [u8; 32],
    /// Max settle Tx D's the settle worker sends CONCURRENTLY within a batch.
    /// `DARKNYX_TEE_SETTLE_SEND_CONCURRENCY`, default 16. Concurrent sends let the
    /// leader co-include settles in one block so they confirm together (the
    /// on-chain throughput lever); 1 reproduces the old one-at-a-time behavior.
    pub settle_send_concurrency: u64,
    /// Maximum whole settlement batches in flight. Default 1 preserves the
    /// production baseline. Values 2..=8 are an explicit benchmark knob:
    /// rolling-ALT mutations remain serialized and continuation notes cannot
    /// re-enter the matcher until their parent Tx D confirms.
    pub settle_batch_concurrency: u8,
    /// Number of Merkle-tree shards (`= vault_config.num_trees`). The settle
    /// worker derives K signer keys (`darknyx/ed25519-signer/v2/{i}`) and
    /// round-robins each match across `(key[j], merkle_tree[j])` so the
    /// concurrent settle Tx D's share no writable account → the leader can
    /// co-include + parallelize them. `DARKNYX_TEE_NUM_TREES`, default 1 (single
    /// shard = the pre-sharding behavior). MUST equal the on-chain
    /// `num_trees` set at `initialize`. Range 1..=16.
    pub num_trees: u8,
}

/// The placeholder base mint used when `DARKNYX_TEE_BASE_MINT` is unset —
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

fn validate_hermes_endpoint(endpoint: &str) -> Result<()> {
    let parsed =
        reqwest::Url::parse(endpoint).context("DARKNYX_TEE_HERMES_ENDPOINT is not a URL")?;
    let loopback = matches!(parsed.host_str(), Some("127.0.0.1" | "localhost" | "::1"));
    if parsed.scheme() != "https" && !(parsed.scheme() == "http" && loopback) {
        bail!("DARKNYX_TEE_HERMES_ENDPOINT must use HTTPS (HTTP is allowed only on loopback)");
    }
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        bail!(
            "DARKNYX_TEE_HERMES_ENDPOINT must not contain credentials, query parameters, or a fragment"
        );
    }
    if !loopback
        && (parsed.scheme() != "https"
            || parsed.host_str() != Some("pyth.dourolabs.app")
            || parsed.path().trim_end_matches('/') != "/hermes")
    {
        bail!(
            "DARKNYX_TEE_HERMES_ENDPOINT must be the upgraded authenticated Pyth router endpoint (or loopback for tests)"
        );
    }
    Ok(())
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

fn parse_mint_value(field: &str, value: &str) -> Result<[u8; 32]> {
    let bytes = bs58::decode(value.trim())
        .into_vec()
        .with_context(|| format!("{field}: invalid base58 mint"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{field}: invalid mint (need 32-byte base58)"))
}

fn validate_symbol(symbol: &str, field: &str) -> Result<()> {
    if symbol.is_empty()
        || symbol.len() > darkpool_matcher::order_canonical::SYMBOL_MAX_LEN
        || !symbol
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'/'))
    {
        bail!(
            "{field} must be 1..={} ASCII market bytes ([A-Za-z0-9_/-])",
            darkpool_matcher::order_canonical::SYMBOL_MAX_LEN
        );
    }
    Ok(())
}

fn validate_feed_id(feed: &str, field: &str) -> Result<()> {
    let feed = feed.strip_prefix("0x").unwrap_or(feed);
    if feed.len() != 64 || !feed.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("{field} must be a 32-byte hex Pyth feed id");
    }
    Ok(())
}

fn normalize_feed_id(feed: &str, field: &str) -> Result<String> {
    validate_feed_id(feed, field)?;
    Ok(feed.strip_prefix("0x").unwrap_or(feed).to_ascii_lowercase())
}

fn validate_deployment_oracle_policy(
    tier: &str,
    mode: OracleMode,
    has_pyth_api_key: bool,
) -> Result<()> {
    match tier {
        "development" => Ok(()),
        "mainnet" if mode != OracleMode::PythRouterQuorumV1 => bail!(
            "mainnet requires DARKNYX_TEE_ORACLE_MODE={}",
            OracleMode::ROUTER_NAME
        ),
        "mainnet" if !has_pyth_api_key => {
            bail!("mainnet requires non-empty DARKNYX_TEE_PYTH_API_KEY")
        }
        "mainnet" => Ok(()),
        other => bail!("DARKNYX_TEE_DEPLOYMENT_TIER must be development or mainnet, got {other:?}"),
    }
}

fn parse_markets_json(raw: &str) -> Result<Vec<MarketSpec>> {
    let rows: Vec<MarketSpecJson> =
        serde_json::from_str(raw).context("DARKNYX_TEE_MARKETS_JSON: invalid JSON")?;
    if rows.is_empty() || rows.len() > MAX_MARKETS_PER_CVM {
        bail!("DARKNYX_TEE_MARKETS_JSON must contain 1..={MAX_MARKETS_PER_CVM} markets");
    }

    let mut symbols = HashSet::new();
    let mut pairs = HashSet::new();
    let mut markets = Vec::with_capacity(rows.len());
    for (index, row) in rows.into_iter().enumerate() {
        let prefix = format!("DARKNYX_TEE_MARKETS_JSON[{index}]");
        validate_symbol(&row.symbol, &format!("{prefix}.symbol"))?;
        let base_mint = parse_mint_value(&format!("{prefix}.base_mint"), &row.base_mint)?;
        let quote_mint = parse_mint_value(&format!("{prefix}.quote_mint"), &row.quote_mint)?;
        if base_mint == quote_mint {
            bail!("{prefix}: base_mint and quote_mint must differ");
        }
        if !symbols.insert(row.symbol.clone()) {
            bail!("{prefix}: duplicate symbol {:?}", row.symbol);
        }
        if !pairs.insert((base_mint, quote_mint)) {
            bail!("{prefix}: duplicate ordered mint pair");
        }
        markets.push(MarketSpec {
            symbol: row.symbol,
            base_mint,
            quote_mint,
            oracle_feed_id: normalize_feed_id(
                &row.oracle_feed_id,
                &format!("{prefix}.oracle_feed_id"),
            )?,
        });
    }
    Ok(markets)
}

/// Defense-in-depth for future config constructors.
///
/// Strict JSON validates every feed before it builds a `MarketSpec`, while the
/// legacy compatibility path can create exactly one oracle-free loadgen market.
/// Consequently only malformed direct/test data can violate this today. Keep
/// the invariant explicit so a future constructor cannot silently introduce an
/// oracle-free book into a multi-market venue.
fn validate_market_oracle_invariant(markets: &[MarketSpec]) -> Result<()> {
    let missing = markets
        .iter()
        .filter(|market| market.oracle_feed_id.is_empty())
        .count();
    if markets.len() > 1 && missing != 0 {
        bail!(
            "internal market configuration invariant: every multi-market entry must have \
             oracle_feed_id; {missing} of {} are missing one",
            markets.len(),
        );
    }
    Ok(())
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
            // when the matcher mints a fee note. Fail fast
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
        ("DARKNYX_TEE_API_KEY", TEST_API_KEY)
            | ("DARKNYX_TEE_API_SECRET", TEST_API_SECRET)
            | ("DARKNYX_TEE_PASSPHRASE", TEST_PASSPHRASE)
    )
}

/// Enforce the boundary between explicit local simulator fixtures and a real
/// CVM boot. Known public test credentials are never accepted outside that
/// simulator mode.
fn validate_auth_mode(dstack_socket: Option<&str>, allow_test_auth: bool) -> Result<()> {
    if allow_test_auth && dstack_socket.is_none() {
        bail!("DARKNYX_TEE_ALLOW_TEST_AUTH is permitted only with DSTACK_SIMULATOR_ENDPOINT");
    }

    if !allow_test_auth {
        for var in [
            "DARKNYX_TEE_API_KEY",
            "DARKNYX_TEE_API_SECRET",
            "DARKNYX_TEE_PASSPHRASE",
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
        let legacy_feed_ids: Vec<String> = std::env::var("DARKNYX_TEE_FEED_IDS")
            .ok()
            .map(|s| {
                s.split(',')
                    .map(|t| t.trim().to_string())
                    .filter(|t| !t.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        let oracle_mode = env_string_or("DARKNYX_TEE_ORACLE_MODE", OracleMode::default().as_str())
            .parse::<OracleMode>()
            .context("DARKNYX_TEE_ORACLE_MODE")?;
        let hermes_endpoint =
            env_string_or("DARKNYX_TEE_HERMES_ENDPOINT", UPGRADED_HERMES_ENDPOINT);
        validate_hermes_endpoint(&hermes_endpoint)?;
        let pyth_api_key = env_nonempty("DARKNYX_TEE_PYTH_API_KEY").map(SecretString);
        let deployment_tier = env_string_or("DARKNYX_TEE_DEPLOYMENT_TIER", "development");
        validate_deployment_oracle_policy(&deployment_tier, oracle_mode, pyth_api_key.is_some())?;

        let dstack_socket = std::env::var("DSTACK_SIMULATOR_ENDPOINT")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let allow_test_auth = parse_bool_env("DARKNYX_TEE_ALLOW_TEST_AUTH", false)?;
        validate_auth_mode(dstack_socket.as_deref(), allow_test_auth)?;
        let base_mint_set = env_nonempty("DARKNYX_TEE_BASE_MINT").is_some();
        let quote_mint_set = env_nonempty("DARKNYX_TEE_QUOTE_MINT").is_some();
        if base_mint_set != quote_mint_set {
            bail!("DARKNYX_TEE_BASE_MINT and DARKNYX_TEE_QUOTE_MINT must be supplied together");
        }
        let market_symbol = env_string_or("DARKNYX_TEE_MARKET_SYMBOL", "SOL-USDC");
        validate_symbol(&market_symbol, "DARKNYX_TEE_MARKET_SYMBOL")?;
        let base_mint = parse_mint_env("DARKNYX_TEE_BASE_MINT", default_base_mint())?;
        let quote_mint = parse_mint_env("DARKNYX_TEE_QUOTE_MINT", default_quote_mint())?;

        let markets_json = env_nonempty("DARKNYX_TEE_MARKETS_JSON");
        if markets_json.is_some() && (base_mint_set || quote_mint_set) {
            bail!(
                "DARKNYX_TEE_MARKETS_JSON cannot be mixed with the legacy \
                 DARKNYX_TEE_BASE_MINT/QUOTE_MINT envs"
            );
        }
        let markets = match markets_json {
            Some(raw) => parse_markets_json(&raw)?,
            None => {
                if legacy_feed_ids.len() > 1 {
                    bail!(
                        "DARKNYX_TEE_FEED_IDS accepts at most one feed in the singular-market \
                         compatibility path; use DARKNYX_TEE_MARKETS_JSON for multiple markets"
                    );
                }
                let oracle_feed_id = legacy_feed_ids
                    .first()
                    .map(|feed| normalize_feed_id(feed, "DARKNYX_TEE_FEED_IDS[0]"))
                    .transpose()?
                    .unwrap_or_default();
                vec![MarketSpec {
                    symbol: market_symbol.clone(),
                    base_mint,
                    quote_mint,
                    oracle_feed_id,
                }]
            }
        };
        validate_market_oracle_invariant(&markets)?;
        let mut seen_feeds = HashSet::new();
        let feed_ids: Vec<String> = markets
            .iter()
            .map(|market| market.oracle_feed_id.clone())
            .filter(|feed| !feed.is_empty() && seen_feeds.insert(feed.clone()))
            .collect();
        if oracle_mode == OracleMode::PythRouterQuorumV1
            && !feed_ids.is_empty()
            && pyth_api_key.is_none()
        {
            bail!(
                "DARKNYX_TEE_PYTH_API_KEY is required when DARKNYX_TEE_ORACLE_MODE={} and feeds are configured",
                OracleMode::ROUTER_NAME
            );
        }
        let governed_market =
            env_nonempty("DARKNYX_TEE_MARKETS_JSON").is_some() || (base_mint_set && quote_mint_set);
        let primary = markets
            .first()
            .expect("market parser guarantees at least one entry");

        Ok(Self {
            markets: markets.clone(),
            http_bind: env_string_or("DARKNYX_TEE_HTTP_BIND", "0.0.0.0:8080"),
            transport_mode: TransportModeConfig::from_env()?,
            tls_bind: env_string_or("DARKNYX_TEE_TLS_BIND", "0.0.0.0:8443"),
            // Empty (compose `${VAR}` with no value) → the default, NOT a
            // literal empty URL that breaks every RPC call.
            solana_rpc_url: env_string_or(
                "DARKNYX_TEE_SOLANA_RPC_URL",
                "https://api.devnet.solana.com",
            ),
            dstack_socket,
            allow_test_auth,
            feed_ids,
            oracle_mode,
            hermes_endpoint,
            pyth_api_key,
            sync_from_slot: parse_u64_env("DARKNYX_TEE_SYNC_FROM_SLOT", 0)?,
            base_mint: primary.base_mint,
            quote_mint: primary.quote_mint,
            governed_market,
            market_symbol: primary.symbol.clone(),
            tick_size: parse_u64_env("DARKNYX_TEE_TICK_SIZE", 1)?,
            min_order_size: parse_u64_env("DARKNYX_TEE_MIN_ORDER_SIZE", 0)?,
            settle_lookup_table: parse_pubkey_env("DARKNYX_TEE_SETTLE_LOOKUP_TABLE")?,
            // Clamp to 100% — the matcher's fee math assumes
            // bps ≤ 10_000 (normally enforced on-chain by
            // set_protocol_config; the CVM matcher isn't gated by it).
            fee_rate_bps: parse_u64_env("DARKNYX_TEE_FEE_RATE_BPS", 30)?.min(10_000),
            protocol_owner_commitment: parse_hex32_env(
                "DARKNYX_TEE_PROTOCOL_OWNER_COMMITMENT",
                [0u8; 32],
            )?,
            settle_send_concurrency: parse_u64_env("DARKNYX_TEE_SETTLE_SEND_CONCURRENCY", 16)?
                .max(1),
            settle_batch_concurrency: parse_u64_env("DARKNYX_TEE_SETTLE_BATCH_CONCURRENCY", 1)?
                .clamp(1, 8) as u8,
            // 1..=16 (vault MAX_TREES). Clamp rather than fail: a 0 or absurd
            // value falls back to a single shard (the safe, pre-sharding path).
            num_trees: parse_u64_env("DARKNYX_TEE_NUM_TREES", 1)?.clamp(1, 16) as u8,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multi_market_json_is_strict_and_deduplicated() {
        let mint_a = bs58::encode([1u8; 32]).into_string();
        let mint_b = bs58::encode([2u8; 32]).into_string();
        let mint_c = bs58::encode([3u8; 32]).into_string();
        let feed = "ab".repeat(32);
        let raw = format!(
            r#"[
                {{"symbol":"SOL-USDC","base_mint":"{mint_a}","quote_mint":"{mint_b}","oracle_feed_id":"{feed}"}},
                {{"symbol":"BTC-USDC","base_mint":"{mint_c}","quote_mint":"{mint_b}","oracle_feed_id":"0x{feed}"}}
            ]"#
        );
        let parsed = parse_markets_json(&raw).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[1].symbol, "BTC-USDC");
        assert_eq!(parsed[1].oracle_feed_id, feed);

        let duplicate = format!(
            r#"[
                {{"symbol":"SOL-USDC","base_mint":"{mint_a}","quote_mint":"{mint_b}","oracle_feed_id":"{feed}"}},
                {{"symbol":"SOL-USDC","base_mint":"{mint_c}","quote_mint":"{mint_b}","oracle_feed_id":"{feed}"}}
            ]"#
        );
        assert!(parse_markets_json(&duplicate)
            .unwrap_err()
            .to_string()
            .contains("duplicate symbol"));

        let missing_feed = format!(
            r#"[
                {{"symbol":"SOL-USDC","base_mint":"{mint_a}","quote_mint":"{mint_b}","oracle_feed_id":"{feed}"}},
                {{"symbol":"BTC-USDC","base_mint":"{mint_c}","quote_mint":"{mint_b}"}}
            ]"#
        );
        assert!(
            parse_markets_json(&missing_feed).is_err(),
            "every strict multi-market row must name its own oracle feed"
        );
    }

    #[test]
    fn legacy_feed_ids_are_canonical_lowercase() {
        assert_eq!(
            normalize_feed_id(&"AB".repeat(32), "legacy").unwrap(),
            "ab".repeat(32)
        );
    }

    #[test]
    fn mainnet_requires_authenticated_router_mode() {
        validate_deployment_oracle_policy("development", OracleMode::PythSolanaPushV1, false)
            .unwrap();
        assert!(
            validate_deployment_oracle_policy("mainnet", OracleMode::PythSolanaPushV1, true,)
                .is_err()
        );
        assert!(validate_deployment_oracle_policy(
            "mainnet",
            OracleMode::PythRouterQuorumV1,
            false,
        )
        .is_err());
        validate_deployment_oracle_policy("mainnet", OracleMode::PythRouterQuorumV1, true).unwrap();
    }

    #[test]
    fn direct_multi_market_data_cannot_bypass_required_oracle_feeds() {
        let mixed = vec![
            MarketSpec {
                symbol: "SOL-USDC".to_string(),
                base_mint: [1; 32],
                quote_mint: [2; 32],
                oracle_feed_id: "aa".repeat(32),
            },
            MarketSpec {
                symbol: "BTC-USDC".to_string(),
                base_mint: [3; 32],
                quote_mint: [2; 32],
                oracle_feed_id: String::new(),
            },
        ];
        let error = validate_market_oracle_invariant(&mixed)
            .expect_err("partial oracle coverage must fail closed at boot");
        assert!(error
            .to_string()
            .contains("every multi-market entry must have oracle_feed_id"));

        let oracle_free = mixed
            .into_iter()
            .map(|mut market| {
                market.oracle_feed_id.clear();
                market
            })
            .collect::<Vec<_>>();
        validate_market_oracle_invariant(&oracle_free)
            .expect_err("an all-oracle-free multi-market venue is unsupported");

        validate_market_oracle_invariant(&[MarketSpec {
            symbol: "LOADGEN".to_string(),
            base_mint: [1; 32],
            quote_mint: [2; 32],
            oracle_feed_id: String::new(),
        }])
        .expect("the singular legacy loadgen path remains oracle-optional");
    }

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
        assert!(is_known_test_credential(
            "DARKNYX_TEE_API_KEY",
            TEST_API_KEY
        ));
        assert!(is_known_test_credential(
            "DARKNYX_TEE_API_SECRET",
            TEST_API_SECRET
        ));
        assert!(is_known_test_credential(
            "DARKNYX_TEE_PASSPHRASE",
            TEST_PASSPHRASE
        ));
        assert!(!is_known_test_credential(
            "DARKNYX_TEE_API_KEY",
            "fresh-production-key"
        ));
    }

    #[test]
    fn pyth_api_key_debug_is_redacted() {
        let secret = SecretString("never-print-this".into());
        assert_eq!(secret.expose(), "never-print-this");
        assert_eq!(format!("{secret:?}"), "[REDACTED]");
        assert!(!format!("{secret:?}").contains(secret.expose()));
    }

    #[test]
    fn hermes_endpoint_rejects_secret_bearing_or_plaintext_remote_urls() {
        validate_hermes_endpoint("https://pyth.dourolabs.app/hermes").unwrap();
        validate_hermes_endpoint("http://127.0.0.1:8080").unwrap();
        assert!(validate_hermes_endpoint("https://pyth.example/hermes").is_err());
        assert!(validate_hermes_endpoint("http://pyth.example/hermes").is_err());
        assert!(validate_hermes_endpoint("https://key@pyth.example/hermes").is_err());
        assert!(validate_hermes_endpoint("https://pyth.example/hermes?key=secret").is_err());
    }
}

#[cfg(test)]
mod transport_mode_tests {
    use super::TransportModeConfig;

    /// `DARKNYX_TEE_TRANSPORT_MODE` is process-global, so these run under one
    /// lock rather than as separate `#[test]`s that would race each other.
    #[test]
    fn transport_mode_parses_and_fails_closed_on_a_typo() {
        const KEY: &str = "DARKNYX_TEE_TRANSPORT_MODE";
        let restore = std::env::var(KEY).ok();

        std::env::remove_var(KEY);
        assert_eq!(
            TransportModeConfig::from_env().unwrap(),
            TransportModeConfig::GatewayTerminated,
            "unset must mean the legacy default"
        );

        std::env::set_var(KEY, "");
        assert_eq!(
            TransportModeConfig::from_env().unwrap(),
            TransportModeConfig::GatewayTerminated,
            "empty must mean the legacy default"
        );

        std::env::set_var(KEY, "ra-tls");
        assert_eq!(
            TransportModeConfig::from_env().unwrap(),
            TransportModeConfig::RaTls
        );

        std::env::set_var(KEY, "  ra-tls  ");
        assert_eq!(
            TransportModeConfig::from_env().unwrap(),
            TransportModeConfig::RaTls,
            "surrounding whitespace must not defeat the match"
        );

        std::env::set_var(KEY, "gateway-terminated");
        assert_eq!(
            TransportModeConfig::from_env().unwrap(),
            TransportModeConfig::GatewayTerminated
        );

        // THE case. A typo must not silently leave the operator on the weaker
        // transport believing they enabled the stronger one.
        for typo in ["ratls", "RA-TLS", "ra_tls", "true", "1", "tls"] {
            std::env::set_var(KEY, typo);
            assert!(
                TransportModeConfig::from_env().is_err(),
                "{typo:?} was silently accepted instead of failing closed"
            );
        }

        match restore {
            Some(v) => std::env::set_var(KEY, v),
            None => std::env::remove_var(KEY),
        }
    }

    #[test]
    fn wire_spellings_match_the_api_vocabulary() {
        // These strings appear in /info and in /transport-attestation's
        // manifest. One vocabulary across config and API.
        assert_eq!(TransportModeConfig::RaTls.as_str(), "ra-tls");
        assert_eq!(
            TransportModeConfig::GatewayTerminated.as_str(),
            "gateway-terminated"
        );
    }
}
