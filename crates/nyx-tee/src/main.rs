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
use nyx_tee::merkle::{MerkleSync, MerkleSyncConfig};
use nyx_tee::oracle::cache::OracleCache;
use nyx_tee::oracle::hermes::HermesClient;
use nyx_tee::oracle::sync::{spawn_oracle_sync, SyncConfig};
#[cfg(feature = "rapidsnark")]
use nyx_tee::prover::RapidsnarkMatchBatchProver;
use nyx_tee::prover::{ArkMatchBatchProver, Prover, PRODUCTION_BATCH_N};
use nyx_tee::settle::worker::SettleWorkerCtx;
use nyx_tee::settle::{
    alt_account, SettleDriver, SettleDriverConfig, SettleScheduler, SettleSchedulerState,
};
use nyx_tee::solana_rpc::SolanaRpcClient;
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    tracing::info!("nyx-tee starting");

    let cfg = nyx_tee::config::Config::from_env()?;
    // Don't log the full Config: `solana_rpc_url` may embed an API key
    // (some providers put it in the path / userinfo). Log the safe
    // fields + the RPC host only (scheme, path, and any user:pass@
    // stripped).
    let rpc_host = cfg
        .solana_rpc_url
        .split("://")
        .nth(1)
        .unwrap_or(&cfg.solana_rpc_url)
        .split('/')
        .next()
        .unwrap_or("")
        .rsplit('@')
        .next()
        .unwrap_or("");
    tracing::info!(
        http_bind = %cfg.http_bind,
        rpc_host = %rpc_host,
        feeds = cfg.feed_ids.len(),
        dstack_socket = cfg.dstack_socket.is_some(),
        "loaded config (solana_rpc_url redacted to host)"
    );

    // ─── 1. dstack handshake ─────────────────────────────────────────
    // PR 4g.3 walk-back: the TEE Ed25519 signer (registered as
    // `vault_config.tee_pubkey`) doubles as the Solana fee-payer.
    // Same Ed25519 seed → same Solana pubkey via
    // `DerivedSigner::solana_keypair()`. One address to fund on
    // devnet, one signature satisfies both the `tee_authority`
    // gate AND the tx-fee responsibility.
    #[allow(clippy::type_complexity)]
    let (api_state, tee_signer_pubkey, settle_signer): (
        _,
        Option<String>,
        Option<Vec<(solana_keypair::Keypair, ed25519_dalek::SigningKey)>>,
    ) = match nyx_tee::boot::probe_dstack().await {
        Ok(signer) => {
            let client = DstackClient::new(None);
            let info = client.info().await?;

            // Derive the bearer-JWT secret from dstack while
            // the client is still in scope. Distinct path from
            // the Ed25519 signer so a compromise of one key
            // material doesn't trivially leak the other.
            let jwt_secret = derive_jwt_secret(&client).await?;

            // Derive the full K-shard signer set (one fee-payer/authority per
            // Merkle-tree shard, at nyx/ed25519-signer/v1/{i}). signers[0] is
            // the primary `signer` from probe_dstack (the /info advertisement +
            // the per-batch lock/verify/ALT/close payer); signers[1..] are the
            // extra shard fee-payers the settle Tx D's round-robin across. ALL K
            // must be registered in vault_config.tee_pubkeys + funded.
            let signers = nyx_tee::keys::ed25519::derive_set(&client, cfg.num_trees).await?;
            tracing::info!(
                num_trees = cfg.num_trees,
                shard_pubkeys = ?signers.iter().map(|s| s.pubkey_base58.clone()).collect::<Vec<_>>(),
                "derived K-shard TEE signer set — register ALL in vault_config.tee_pubkeys + fund each"
            );

            let signer_pubkey = signer.pubkey_base58.clone();
            tracing::info!(
                tee_signer_pubkey = %signer_pubkey,
                "TEE Ed25519 signer (shard 0) also acts as Solana fee-payer; \
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
            // Capture the K-shard signer material for the settle driver: each
            // shard's Solana fee-payer keypair + Ed25519 signing key (same
            // seed). Held only in the driver's worker context, never on ApiState.
            let settle_signer = Some(
                signers
                    .iter()
                    .map(|s| (s.solana_keypair(), s.key.clone()))
                    .collect::<Vec<_>>(),
            );
            (
                nyx_tee::api::ApiState::from_boot(boot_info, &signer, dstack, jwt_secret),
                Some(signer_pubkey),
                settle_signer,
            )
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "dstack probe failed; entering degraded boot. /health + /info \
                 will serve stub data; /attestation returns 503. The settle \
                 pipeline is also disabled — no TEE signer available."
            );
            (nyx_tee::api::ApiState::for_tests(), None, None)
        }
    };

    // ─── 2. Shared runtime ───────────────────────────────────────────
    // Build the match config up front so its mints can seed the
    // shared MatcherState — the order intake needs them to verify
    // each input-note opening against the signed commitment (4g.7a).
    let match_config = dev_match_config(&cfg);
    tracing::info!(
        fee_rate_bps = match_config.fee_rate_bps,
        protocol_owner_set = (match_config.protocol_owner_commitment != [0u8; 32]),
        "matcher fee config (fee notes mint when fee_rate_bps > 0)"
    );
    // Fees on but no owner set ⇒ fee notes mint to the zero owner and are
    // unclaimable. Flag the misconfiguration loudly (don't hard-fail: a
    // fee-free or throwaway dev run is legitimate).
    if match_config.fee_rate_bps > 0 && match_config.protocol_owner_commitment == [0u8; 32] {
        tracing::warn!(
            "fee_rate_bps > 0 but NYX_TEE_PROTOCOL_OWNER_COMMITMENT is unset — protocol \
             fee notes will mint to a ZERO owner and be UNCLAIMABLE; set the owner \
             commitment, or set NYX_TEE_FEE_RATE_BPS=0"
        );
    }
    // Capture the values the settle driver needs before `match_config`
    // is moved into the matcher driver below ([u8; 32] is Copy).
    let settle_base_mint = match_config.base_mint;
    let settle_quote_mint = match_config.quote_mint;
    let settle_protocol_owner = match_config.protocol_owner_commitment;
    // Also for the /instruments metadata (captured before the move).
    let market_tick_size = match_config.tick_size;
    let market_min_order_size = match_config.min_order_size;
    let matcher_state = Arc::new(RwLock::new(
        MatcherState::new()
            .with_market(match_config.base_mint, match_config.quote_mint)
            .with_fee_rate_bps(match_config.fee_rate_bps),
    ));
    let oracle = OracleCache::new();
    let current_slot = Arc::new(AtomicU64::new(1));
    // Compute-unit price bid (micro-lamports/CU) the settle worker prepends to
    // every settle-path tx. Refreshed by the priority-fee poller (7e) from
    // getRecentPrioritizationFees; starts at 0 (no bid until the first poll).
    let current_priority_fee = Arc::new(AtomicU64::new(0));

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
            // Page each tick into ≤N-match batches matching the N=16
            // VALID_MATCH_BATCH settle circuit.
            max_matches_per_batch: PRODUCTION_BATCH_N,
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

    // ─── 5. Settle scheduler + live settle driver (PR 4g.7e) ──────────
    // The scheduler accumulates per-match jobs; when the TEE is fully
    // configured (signer + RPC + N=16 prover) a `SettleDriver` drives
    // each batch through the full on-chain pipeline (lock → prove →
    // verify → ALT → settle → close) and evicts the spent openings.
    // Missing any dependency (degraded boot, prover zkey absent in a
    // local dev run) → enqueue-only, logged below.
    let settle_state = Arc::new(RwLock::new(SettleSchedulerState::default()));
    let settle_driver: Option<SettleDriver> = match settle_signer {
        Some(shard_signers) => {
            // Split the K (keypair, signing_key) pairs into the two parallel
            // Vecs the worker holds (tee_keypairs[j] pairs with signing_keys[j]).
            let (tee_keypairs, signing_keys): (Vec<_>, Vec<_>) = shard_signers.into_iter().unzip();
            build_settle_driver(
                &cfg,
                tee_keypairs,
                signing_keys,
                settle_state.clone(),
                matcher_state.clone(),
                current_slot.clone(),
                current_priority_fee.clone(),
                settle_base_mint,
                settle_quote_mint,
                settle_protocol_owner,
            )
            .map(|d| {
                tracing::info!(
                    tee_signer = ?tee_signer_pubkey,
                    "settle driver constructed — live settle pipeline ENABLED"
                );
                Some(d)
            })
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "settle driver unavailable; scheduler is enqueue-only");
                None
            })
        }
        None => {
            tracing::warn!("no TEE signer derived (degraded boot); settle pipeline disabled");
            None
        }
    };
    let _scheduler_handle =
        SettleScheduler::spawn_with_settle(matches_rx, settle_state.clone(), settle_driver);

    // ─── 6. Attach a Solana RPC client to ApiState for visibility ─────
    // (The settle driver owns its OWN client; this one only backs
    // operator-facing read endpoints.)
    let api_state = if tee_signer_pubkey.is_some() {
        match SolanaRpcClient::new(&cfg.solana_rpc_url) {
            Ok(rpc) => api_state.with_solana_rpc(rpc),
            Err(e) => {
                tracing::warn!(error = %e, "ApiState Solana RPC client construction failed");
                api_state
            }
        }
    } else {
        api_state
    };

    // ─── 7. Attach matcher + settle state + instruments to ApiState ───
    let instruments = vec![nyx_tee::api::instruments::InstrumentInfo {
        symbol: "SOL-USDC".to_string(),
        base_mint: settle_base_mint,
        quote_mint: settle_quote_mint,
        tick_size: market_tick_size,
        min_order_size: market_min_order_size,
        oracle_feed_id: cfg.feed_ids.first().cloned().unwrap_or_default(),
    }];
    let api_state = api_state
        .with_matcher_runtime(matcher_state, current_slot, oracle.clone())
        .with_settle_state(settle_state)
        .with_instruments(instruments);

    let api_state = Arc::new(api_state);

    // ─── 7b. Spawn the Merkle mirror sync (Phase 2b) ──────────────────
    // Cold-boots the mirror from the vault program's history, then
    // live-polls. Uses its OWN read-only RPC client (independent of the
    // settle driver's). Best-effort: a failure here only means /tree/*
    // serves an empty/stale mirror — clients can always read
    // VaultConfig directly. Gated on a real boot (signer present) since
    // degraded boot has no real cluster to sync against.
    if tee_signer_pubkey.is_some() {
        match SolanaRpcClient::new(&cfg.solana_rpc_url) {
            Ok(rpc) => {
                let mirror = api_state.merkle_mirror.clone();
                let vault_program_id = nyx_tee::settle::vault::vault_program_id();
                let (vault_config_pda, _) = nyx_tee::settle::vault::vault_config_pda();
                tokio::spawn(async move {
                    let mut sync = MerkleSync::new(
                        rpc,
                        mirror,
                        vault_program_id,
                        vault_config_pda,
                        MerkleSyncConfig {
                            from_slot: cfg.sync_from_slot,
                            ..MerkleSyncConfig::default()
                        },
                    );
                    if let Err(e) = sync.cold_boot().await {
                        tracing::warn!(error = %e, "merkle cold-boot failed; live loop will recover");
                    }
                    sync.run().await;
                });
                tracing::info!("merkle mirror sync spawned (cold-boot + live poll)");
            }
            Err(e) => tracing::warn!(
                error = %e,
                "merkle sync RPC client construction failed; /tree/* serves an empty mirror"
            ),
        }
    }

    // ─── 7c. Slot poller — keep current_slot ≈ the real cluster slot ──
    // The settle driver stamps the BatchValidityMarker expiry as
    // current_slot + ttl; the on-chain verify_match_batch rejects it
    // (InvalidMarkerExpiry) unless it's in the future relative to the
    // real cluster clock. The matcher also reads current_slot for
    // expiry sweeps. Without this, current_slot stays at its init value
    // (1) and every settle reverts. Polls the cluster slot every ~2 s
    // into the SAME Arc the matcher + settle scheduler hold.
    if tee_signer_pubkey.is_some() {
        match SolanaRpcClient::new(&cfg.solana_rpc_url) {
            Ok(rpc) => {
                let slot = api_state.current_slot.clone();
                tokio::spawn(async move {
                    let mut ticks: u64 = 0;
                    loop {
                        match rpc.get_latest_blockhash().await {
                            Ok(bh) => {
                                slot.store(bh.context_slot, std::sync::atomic::Ordering::Relaxed);
                                // Heartbeat: first poll + then ~every 30 s, so
                                // current_slot is observable in the logs.
                                if ticks.is_multiple_of(15) {
                                    tracing::info!(
                                        slot = bh.context_slot,
                                        "slot poller: current_slot updated"
                                    );
                                }
                            }
                            // WARN (not debug) — a stuck current_slot breaks
                            // the settle marker expiry; we must see this.
                            Err(e) => {
                                tracing::warn!(error = %e, "slot poll FAILED; current_slot stale")
                            }
                        }
                        ticks = ticks.wrapping_add(1);
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    }
                });
                tracing::info!("slot poller spawned (current_slot <- cluster)");
            }
            Err(e) => tracing::warn!(error = %e, "slot poller RPC construction failed"),
        }
    }

    // ─── 7e. Priority-fee poller — bid from getRecentPrioritizationFees ──
    // The settle worker prepends a SetComputeUnitPrice ix (sized to its
    // right-sized CU limits) to every settle-path tx; this task keeps the bid
    // current. It polls the recent cluster prioritization fees every ~10 s,
    // folds them into the 75th-percentile bid (capped), and stores it in the
    // SAME Arc the worker reads. A quiet network (devnet) yields 0 → no price
    // ix, so this is a no-op there and only starts paying under real
    // congestion. Cap overridable via NYX_TEE_PRIORITY_FEE_CAP.
    if tee_signer_pubkey.is_some() {
        let cap = std::env::var("NYX_TEE_PRIORITY_FEE_CAP")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(nyx_tee::settle::priority::DEFAULT_PRIORITY_FEE_CAP_MICRO_LAMPORTS);
        match SolanaRpcClient::new(&cfg.solana_rpc_url) {
            Ok(rpc) => {
                let fee = current_priority_fee.clone();
                tokio::spawn(async move {
                    let mut ticks: u64 = 0;
                    loop {
                        // Empty writable set → global recent fees (broad
                        // congestion signal). Could be narrowed to the vault
                        // config PDA (the hottest written account) later.
                        match rpc.get_recent_prioritization_fees(&[]).await {
                            Ok(samples) => {
                                let bid = nyx_tee::settle::priority::priority_fee_bid(
                                    &samples
                                        .iter()
                                        .map(|s| s.prioritization_fee)
                                        .collect::<Vec<_>>(),
                                    cap,
                                );
                                fee.store(bid, std::sync::atomic::Ordering::Relaxed);
                                if ticks.is_multiple_of(6) {
                                    tracing::info!(
                                        priority_fee_micro_lamports = bid,
                                        samples = samples.len(),
                                        "priority-fee poller: bid updated"
                                    );
                                }
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "priority-fee poll failed; bid stale")
                            }
                        }
                        ticks = ticks.wrapping_add(1);
                        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                    }
                });
                tracing::info!(
                    priority_fee_cap_micro_lamports = cap,
                    "priority-fee poller spawned (bid <- getRecentPrioritizationFees)"
                );
            }
            Err(e) => tracing::warn!(error = %e, "priority-fee poller RPC construction failed"),
        }
    }

    // ─── 7d. Spawn the fills router ───────────────────────────────────
    // Fans the matcher's global FillMemo broadcast into per-account channels
    // (the leak guard behind `/ws/fills`). No-op in degraded boot (no matcher).
    nyx_tee::api::fills_router::spawn_fills_router(api_state.clone());

    // ─── 8. Build router + bind listener + serve ──────────────────────
    let app = nyx_tee::api::build_router(api_state);
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

/// Construct the live [`SettleDriver`] from the TEE signer + config.
/// Fails (→ enqueue-only) if the RPC client or the N=16 proving key
/// can't be constructed. The zkey path defaults to the in-image
/// `/circuits/build`; set `NYX_TEE_CIRCUITS_DIR` to point at a local
/// `circuits/build` for dev runs.
#[allow(clippy::too_many_arguments)]
fn build_settle_driver(
    cfg: &nyx_tee::config::Config,
    tee_keypairs: Vec<solana_keypair::Keypair>,
    signing_keys: Vec<ed25519_dalek::SigningKey>,
    settle_state: Arc<RwLock<SettleSchedulerState>>,
    matcher_state: Arc<RwLock<MatcherState>>,
    current_slot: Arc<AtomicU64>,
    current_priority_fee: Arc<AtomicU64>,
    base_mint: [u8; 32],
    quote_mint: [u8; 32],
    protocol_owner_commitment: [u8; 32],
) -> anyhow::Result<SettleDriver> {
    let rpc = SolanaRpcClient::new(&cfg.solana_rpc_url)?;
    let circuits_dir =
        std::env::var("NYX_TEE_CIRCUITS_DIR").unwrap_or_else(|_| "/circuits/build".to_string());
    // The N=16 proving key is ~74 MB; `read_zkey` parses it
    // synchronously here, before the HTTP surface comes up. Fast in a
    // release build (the CVM), but a plain debug build takes ~minutes —
    // log around it so a slow boot doesn't look hung.
    // Prover backend select (A/B): NYX_TEE_PROVER=ark (default) | rapidsnark.
    // Both backends ship in the image (rapidsnark feature on for the amd64
    // build), so flipping the env A/Bs proving on the SAME image + instance and
    // rolls back instantly without a rebuild/re-attestation. Witness gen is
    // ark-circom either way; only the prove step differs.
    let backend = std::env::var("NYX_TEE_PROVER").unwrap_or_else(|_| "ark".to_string());
    tracing::info!(
        circuits_dir,
        n = PRODUCTION_BATCH_N,
        backend,
        "loading VALID_MATCH_BATCH proving key…"
    );
    let prover: Arc<dyn Prover> = match backend.as_str() {
        "rapidsnark" => {
            #[cfg(feature = "rapidsnark")]
            {
                Arc::new(
                    RapidsnarkMatchBatchProver::load(&circuits_dir, PRODUCTION_BATCH_N).map_err(
                        |e| {
                            anyhow::anyhow!(
                                "load rapidsnark N={PRODUCTION_BATCH_N} from {circuits_dir}: {e}"
                            )
                        },
                    )?,
                )
            }
            #[cfg(not(feature = "rapidsnark"))]
            {
                anyhow::bail!(
                    "NYX_TEE_PROVER=rapidsnark but this binary was built without the \
                     `rapidsnark` feature"
                );
            }
        }
        "ark" => Arc::new(
            ArkMatchBatchProver::load(&circuits_dir, PRODUCTION_BATCH_N).map_err(|e| {
                anyhow::anyhow!("load ark N={PRODUCTION_BATCH_N} from {circuits_dir}: {e}")
            })?,
        ),
        other => anyhow::bail!("unknown NYX_TEE_PROVER={other:?} (expected `ark` or `rapidsnark`)"),
    };
    tracing::info!(backend, "VALID_MATCH_BATCH proving key loaded");

    // Static settle ALT (vault_config + instructions_sysvar +
    // system_program), created at devnet-setup. When its on-chain
    // address is supplied via NYX_TEE_SETTLE_LOOKUP_TABLE, stack it
    // under the per-batch ALT so the v0 settle tx (Tx D) stays under
    // the 1232-byte cap on the real-mint path. The address list MUST
    // match the on-chain ALT's contents in order — `static_alt_addresses()`
    // mirrors the SDK's `extendLookupTable` order exactly.
    let static_alt = cfg.settle_lookup_table.map(|lut| {
        alt_account(
            solana_address::Address::new_from_array(lut),
            nyx_tee::settle::settle_batched::static_alt_addresses(cfg.num_trees),
        )
    });
    match &static_alt {
        Some(a) => tracing::info!(alt = %a.key, "static settle ALT threaded into settle worker"),
        None => tracing::warn!(
            "no static settle ALT (NYX_TEE_SETTLE_LOOKUP_TABLE unset) — \
             real-mint settle tx may exceed 1232 bytes"
        ),
    }

    let ctx = SettleWorkerCtx {
        rpc,
        tee_keypairs: tee_keypairs.into_iter().map(Arc::new).collect(),
        signing_keys: signing_keys.into_iter().map(Arc::new).collect(),
        prover,
        static_alt,
        alt_pool: Arc::new(tokio::sync::Mutex::new(
            nyx_tee::settle::alt_pool::AltPool::new(),
        )),
        settle_state,
        confirm_timeout: Duration::from_secs(60),
        current_priority_fee: current_priority_fee.clone(),
        settle_send_concurrency: cfg.settle_send_concurrency as usize,
    };

    Ok(SettleDriver {
        ctx,
        matcher_state,
        current_slot,
        cfg: SettleDriverConfig {
            base_mint,
            quote_mint,
            protocol_owner_commitment,
            circuit_n: PRODUCTION_BATCH_N,
        },
    })
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
///   - `fee_rate_bps`             from Config (NYX_TEE_FEE_RATE_BPS, default 30)
fn dev_match_config(cfg: &nyx_tee::config::Config) -> MatchConfig {
    // Mints + tick + min + fee come from Config (env-overridable) so a
    // real settle can point the matcher at the on-chain mints the
    // deposited notes use AND charge a real protocol fee (so fee notes
    // actually mint). They default to deterministic placeholders / a
    // 30 bps fee, so dev / loadgen behaviour is sane when unset. The
    // remaining fields are dev defaults (circuit breaker effectively
    // disabled, 2 s batch).
    MatchConfig {
        base_mint: cfg.base_mint,
        quote_mint: cfg.quote_mint,
        tick_size: cfg.tick_size,
        min_order_size: cfg.min_order_size,
        circuit_breaker_bps: 100_000,
        batch_ms: 2000,
        // Config clamps to ≤ 10_000, so the u16 cast is lossless.
        fee_rate_bps: cfg.fee_rate_bps as u16,
        protocol_owner_commitment: cfg.protocol_owner_commitment,
    }
}
