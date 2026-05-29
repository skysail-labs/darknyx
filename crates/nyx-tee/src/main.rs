//! `nyx-tee` — the in-TEE matching engine.
//!
//! Production entry point. All real module logic lives in the
//! sibling `lib.rs` so integration tests can exercise it without
//! the binary boot path. This file orchestrates startup:
//!
//!   1. Init tracing.
//!   2. Load config from env.
//!   3. Dstack handshake (PR 4a) → derive Ed25519 signer +
//!      JWT secret + capture app_id / instance_id / compose_hash /
//!      MRTD.
//!   4. Construct shared runtime (matcher state, oracle cache,
//!      current_slot, matches channel).
//!   5. Spawn long-running tokio tasks:
//!      - `MatcherDriver` (PR 4c) — ticks every `BATCH_MS`.
//!      - `oracle_sync` (PR 4b) — refreshes the cache from Hermes.
//!      - Settle-output drainer — placeholder until PR 4f wires
//!        the real settle scheduler.
//!   6. Thread the shared matcher state into `ApiState` via
//!      `with_matcher_runtime` so the orders handlers (PR 4e.3) can
//!      read + write the same book the driver does.
//!   7. Bind the configured HTTP socket + `axum::serve(...)` until
//!      Ctrl-C / listener drop.
//!
//! Degraded boot: if the dstack socket isn't reachable, we still
//! spin up the matcher (the orders handlers stay live) and skip
//! oracle sync; `/attestation` returns 503; `/info` serves stub
//! values. This is the standard dev-machine experience without a
//! running simulator.

use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use darkpool_matcher::config::MatchConfig;
use darkpool_matcher::match_result::RunBatchOutput;
use dstack_sdk::dstack_client::DstackClient;
use nyx_tee::matcher::{DriverConfig, MatcherDriver, MatcherState, DEFAULT_MAX_ORACLE_AGE_MS};
use nyx_tee::oracle::cache::OracleCache;
use nyx_tee::oracle::hermes::HermesClient;
use nyx_tee::oracle::sync::{spawn_oracle_sync, SyncConfig};
use nyx_tee::settle::SettleScheduler;
use nyx_tee::solana_rpc::SolanaRpcClient;
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    tracing::info!("nyx-tee starting");

    let cfg = nyx_tee::config::Config::from_env()?;
    tracing::info!(?cfg, "loaded config");

    // ─── 1. dstack handshake ─────────────────────────────────────────
    // PR 4g.3 walk-back: the TEE Ed25519 signer (registered as
    // `vault_config.tee_pubkey`) doubles as the Solana fee-payer.
    // Same Ed25519 seed → same Solana pubkey via
    // `DerivedSigner::solana_keypair()`. One address to fund on
    // devnet, one signature satisfies both the `tee_authority`
    // gate AND the tx-fee responsibility.
    let (api_state, tee_signer_pubkey): (_, Option<String>) =
        match nyx_tee::boot::probe_dstack().await {
            Ok(signer) => {
                let client = DstackClient::new(None);
                let info = client.info().await?;

                // Derive the bearer-JWT secret from dstack while
                // the client is still in scope. Distinct path from
                // the Ed25519 signer so a compromise of one key
                // material doesn't trivially leak the other.
                let jwt_secret = derive_jwt_secret(&client).await?;

                let signer_pubkey = signer.pubkey_base58.clone();
                tracing::info!(
                    tee_signer_pubkey = %signer_pubkey,
                    "TEE Ed25519 signer also acts as Solana fee-payer; \
                     verify this address holds SOL on the target cluster \
                     (devnet: `solana airdrop 5 <pubkey>`)"
                );

                let dstack = Arc::new(client);
                let boot_info = nyx_tee::api::BootAppInfo {
                    app_id: info.app_id,
                    instance_id: info.instance_id,
                    app_name: info.app_name,
                    device_id: info.device_id,
                    compose_hash: info.compose_hash,
                    mrtd: info.tcb_info.mrtd,
                };
                (
                    nyx_tee::api::ApiState::from_boot(boot_info, &signer, dstack, jwt_secret),
                    Some(signer_pubkey),
                )
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "dstack probe failed; entering degraded boot. /health + /info \
                     will serve stub data; /attestation returns 503. The settle \
                     pipeline is also disabled — no TEE signer available."
                );
                (nyx_tee::api::ApiState::for_tests(), None)
            }
        };

    // ─── 2. Shared runtime ───────────────────────────────────────────
    // Build the match config up front so its mints can seed the
    // shared MatcherState — the order intake needs them to verify
    // each input-note opening against the signed commitment (4g.7a).
    let match_config = dev_match_config();
    let matcher_state = Arc::new(RwLock::new(
        MatcherState::new().with_market(match_config.base_mint, match_config.quote_mint),
    ));
    let oracle = OracleCache::new();
    let current_slot = Arc::new(AtomicU64::new(1));

    // Matches channel — capacity 1024 is plenty: the matcher
    // produces at most one `RunBatchOutput` per tick (default
    // 2 s); the drainer (or future settle scheduler) reads
    // continuously. If we ever block here, the matcher's `tick()`
    // returns Err and shuts down — which is the right behaviour
    // when the settle path is unhealthy.
    let (matches_tx, matches_rx) = mpsc::channel::<RunBatchOutput>(1024);

    // ─── 3. Spawn matcher driver ──────────────────────────────────────
    let driver = MatcherDriver {
        state: matcher_state.clone(),
        oracle: oracle.clone(),
        current_slot: current_slot.clone(),
        matches_tx,
        cfg: DriverConfig {
            match_config,
            // First configured feed drives this single-market
            // build. PR 4g+ will spawn one driver per market.
            feed_id: cfg
                .feed_ids
                .first()
                .cloned()
                .unwrap_or_else(|| "no-feed-configured".to_string()),
            batch_ms: 2000,
            max_oracle_age_ms: DEFAULT_MAX_ORACLE_AGE_MS,
        },
    };
    let _driver_handle = driver.spawn();
    tracing::info!("matcher driver spawned (BATCH_MS=2000)");

    // ─── 4. Spawn oracle sync if feeds configured ─────────────────────
    let _oracle_handle: Option<JoinHandle<()>> = if cfg.feed_ids.is_empty() {
        tracing::warn!(
            "no NYX_TEE_FEED_IDS configured; oracle sync NOT spawned. \
             Matcher ticks will skip (oracle stale) until at least one \
             feed is wired. Set NYX_TEE_FEED_IDS=<hex>,<hex>,... to enable."
        );
        None
    } else {
        let client = HermesClient::new()?;
        let handle = spawn_oracle_sync(
            oracle.clone(),
            client,
            SyncConfig {
                feed_ids: cfg.feed_ids.clone(),
                interval: Duration::from_secs(1),
            },
        );
        tracing::info!(feed_count = cfg.feed_ids.len(), "oracle sync task spawned");
        Some(handle)
    };

    // ─── 5. Settle scheduler (PR 4g.1) ────────────────────────────────
    // Replaces the prior `drain_matches` stub. Currently accumulates
    // jobs in `Queued` — PRs 4g.3 / 4g.5 / 4g.6 will plug stage
    // workers in and drive jobs to `Done`. The matcher's
    // `send().await` is fed continuously regardless of stage
    // progress (the channel capacity is 1024, and ingestion is a
    // brief write-lock per batch).
    let (_scheduler_handle, settle_state) = SettleScheduler::spawn(matches_rx);

    // ─── 6. Construct Solana RPC client (PR 4g.2 / 4g.3) ──────────────
    // Pointed at the configured cluster URL. The TEE signer's
    // Solana `Keypair` (which IS the fee-payer; see step 1's
    // walk-back) lives in the settle stage workers' closure
    // captures, not on ApiState. Only the pubkey is surfaced for
    // operator visibility.
    let api_state = if let Some(pubkey) = tee_signer_pubkey.as_ref() {
        let rpc = SolanaRpcClient::new(&cfg.solana_rpc_url)?;
        tracing::info!(
            endpoint = cfg.solana_rpc_url,
            tee_signer = %pubkey,
            "Solana RPC client constructed; settle pipeline workers use the TEE \
             signer for both tee_authority and fee-payer roles"
        );
        api_state.with_solana_rpc(rpc)
    } else {
        tracing::warn!("no TEE signer derived (degraded boot); settle pipeline disabled");
        api_state
    };

    // ─── 7. Attach matcher + settle state to ApiState ─────────────────
    let api_state = api_state
        .with_matcher_runtime(matcher_state, current_slot, oracle.clone())
        .with_settle_state(settle_state);

    // ─── 8. Build router + bind listener + serve ──────────────────────
    let app = nyx_tee::api::build_router(Arc::new(api_state));
    let addr: SocketAddr = cfg
        .http_bind
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid NYX_TEE_HTTP_BIND={:?}: {e}", cfg.http_bind))?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(
        local_addr = %listener.local_addr().unwrap_or(addr),
        "nyx-tee HTTP listening — /health /info /attestation /auth/token /orders"
    );

    axum::serve(listener, app).await?;

    tracing::info!("nyx-tee exiting");
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_env("NYX_TEE_LOG")
        .unwrap_or_else(|_| EnvFilter::new("info,nyx_tee=debug"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();
}

/// Derive the bearer-JWT HS256 secret from dstack. Uses a path
/// distinct from the Ed25519 signer so the two key materials are
/// independent (compromise of one shouldn't trivially leak the
/// other). Same path → same secret across CVM restarts on the
/// same `app_id`, so bearer tokens issued before a restart remain
/// valid until they expire.
async fn derive_jwt_secret(client: &DstackClient) -> anyhow::Result<[u8; 32]> {
    let resp = client
        .get_key(Some("nyx/jwt-secret/v1".to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("dstack.get_key('nyx/jwt-secret/v1') failed: {e}"))?;
    let bytes = resp
        .decode_key()
        .map_err(|e| anyhow::anyhow!("dstack.get_key returned undecodable JWT key: {e}"))?;
    let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "dstack returned {} bytes for JWT secret; expected 32",
            bytes.len()
        )
    })?;
    Ok(arr)
}

/// Hardcoded dev `MatchConfig`. Production reads this from the
/// on-chain `MatchingConfig` PDA per market — a separate Solana
/// RPC poller (later PR) keeps it in sync. The numbers here are
/// the same ones the litesvm regression tests use, so dev matches
/// reproduce on devnet without surprises:
///
///   - `tick_size = 1`            (no per-market tick rounding)
///   - `min_order_size = 0`       (accept any size in dev)
///   - `circuit_breaker_bps`      effectively disabled
///     (`100_000` = 1000% drift band)
///   - `batch_ms = 2000`          (D5 default)
///   - `fee_rate_bps = 0`         (dev: no fee)
fn dev_match_config() -> MatchConfig {
    // Mints are inert in the matching algorithm itself — they're
    // only there so the on-chain settle ix's per-mint balance
    // checks have something to compare against. Use deterministic
    // placeholders.
    let mut base_mint = [0u8; 32];
    base_mint[0] = 1;
    base_mint[31] = 0xb1;
    let mut quote_mint = [0u8; 32];
    quote_mint[0] = 1;
    quote_mint[31] = 0x9e;

    MatchConfig {
        base_mint,
        quote_mint,
        tick_size: 1,
        min_order_size: 0,
        circuit_breaker_bps: 100_000,
        batch_ms: 2000,
        fee_rate_bps: 0,
        protocol_owner_commitment: [0u8; 32],
    }
}
