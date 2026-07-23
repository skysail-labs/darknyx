//! `darknyx-tee` — the in-TEE matching engine.
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
//! Fail-closed boot: a dstack/KMS probe failure terminates production startup.
//! The test-only `ApiState::for_tests()` fallback is available solely when
//! `DARKNYX_TEE_ALLOW_TEST_AUTH=1` and `DSTACK_SIMULATOR_ENDPOINT` are both set.

use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use darknyx_tee::matcher::{
    DriverConfig, MatcherDriver, MatcherState, TradingGate, DEFAULT_MAX_ORACLE_AGE_MS,
};
use darknyx_tee::merkle::{MerkleSync, MerkleSyncConfig};
use darknyx_tee::oracle::cache::OracleCache;
use darknyx_tee::oracle::hermes::HermesClient;
use darknyx_tee::oracle::sync::{spawn_oracle_sync, SyncConfig};
#[cfg(feature = "icicle")]
use darknyx_tee::prover::IcicleMatchBatchProver;
#[cfg(feature = "rapidsnark")]
use darknyx_tee::prover::RapidsnarkMatchBatchProver;
use darknyx_tee::prover::{ArkMatchBatchProver, Prover, PRODUCTION_BATCH_N};
use darknyx_tee::settle::worker::SettleWorkerCtx;
use darknyx_tee::settle::{
    alt_account, SettleDriver, SettleDriverConfig, SettleScheduler, SettleSchedulerState,
};
use darknyx_tee::solana_rpc::{Commitment, SolanaRpcClient};
use darkpool_matcher::config::MatchConfig;
use darkpool_matcher::match_result::RunBatchOutput;
use dstack_sdk::dstack_client::DstackClient;
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    tracing::info!("darknyx-tee starting");

    let cfg = darknyx_tee::config::Config::from_env()?;
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

    // Host-CPU profile (PERF-INV-01). Emitted before the handshake so a
    // throttled/oversubscribed Phala host is visible in the boot log even if
    // startup later fails. Compare `singlethread_mops_per_s` + `effective_cpus`
    // + `nr_throttled` against the fast-baseline image to localize the 10×
    // proving regression to the host without needing `phala ssh`.
    darknyx_tee::boot::log_host_cpu_profile();

    // ─── 1. dstack handshake ─────────────────────────────────────────
    // PR 4g.3 walk-back: the TEE Ed25519 signer (registered as
    // `vault_config.tee_pubkey`) doubles as the Solana fee-payer.
    // Same Ed25519 seed → same Solana pubkey via
    // `DerivedSigner::solana_keypair()`. One address to fund on
    // devnet, one signature satisfies both the `tee_authority`
    // gate AND the tx-fee responsibility.
    #[allow(clippy::type_complexity)]
    let (api_state, tee_signer_pubkey, tee_signer_pubkeys, settle_signer): (
        _,
        Option<String>,
        Option<Vec<[u8; 32]>>,
        Option<Vec<(solana_keypair::Keypair, ed25519_dalek::SigningKey)>>,
    ) = match darknyx_tee::boot::probe_dstack().await {
        Ok(signer) => {
            let client = DstackClient::new(None);
            let info = client.info().await?;

            // Derive the bearer-JWT secret from dstack while
            // the client is still in scope. Distinct path from
            // the Ed25519 signer so a compromise of one key
            // material doesn't trivially leak the other.
            let jwt_secret = derive_jwt_secret(&client).await?;

            // Derive the full K-shard signer set (one fee-payer/authority per
            // Merkle-tree shard, at darknyx/ed25519-signer/v2/{i}). signers[0] is
            // the primary `signer` from probe_dstack (the /info advertisement +
            // the per-batch lock/verify/ALT/close payer); signers[1..] are the
            // extra shard fee-payers the settle Tx D's round-robin across. ALL K
            // must be registered in vault_config.tee_pubkeys + funded.
            let signers = darknyx_tee::keys::ed25519::derive_set(&client, cfg.num_trees).await?;
            let shard_pubkeys: Vec<String> =
                signers.iter().map(|s| s.pubkey_base58.clone()).collect();
            let shard_pubkey_bytes: Vec<[u8; 32]> =
                signers.iter().map(|s| s.pubkey_bytes()).collect();
            // Bind the WHOLE settle-key set into the attestation report_data.
            let signer_set_hash = darknyx_tee::keys::ed25519::signer_set_hash(&signers);
            tracing::info!(
                num_trees = cfg.num_trees,
                shard_pubkeys = ?shard_pubkeys,
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
            let boot_info = darknyx_tee::api::BootAppInfo {
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
                darknyx_tee::api::ApiState::from_boot(
                    boot_info,
                    &signer,
                    dstack,
                    jwt_secret,
                    cfg.num_trees,
                )
                .with_shard_pubkeys(shard_pubkeys)
                .with_signer_set_hash(signer_set_hash),
                Some(signer_pubkey),
                Some(shard_pubkey_bytes),
                settle_signer,
            )
        }
        Err(e) => {
            if !cfg.allow_test_auth {
                return Err(e).context(
                    "dstack/KMS probe failed; refusing production startup (test auth is disabled)",
                );
            }
            tracing::warn!(
                error = %e,
                "dstack simulator probe failed with DARKNYX_TEE_ALLOW_TEST_AUTH=1; \
                 entering EXPLICIT LOCAL TEST MODE with public fixture credentials. \
                 Never set this flag in a CVM."
            );
            (darknyx_tee::api::ApiState::for_tests(), None, None, None)
        }
    };
    let boot_session_id = api_state.boot_session_id;
    let trading_gate = api_state.trading_gate.clone();

    // ─── 2. Shared runtime ───────────────────────────────────────────
    // Build the match config up front so its mints can seed the
    // shared MatcherState — the order intake needs them to verify
    // each input-note opening against the signed commitment (4g.7a).
    let mut match_config = dev_match_config(&cfg);
    // In a real-settlement boot, finalized on-chain governance is mandatory.
    // VALID_MATCH_BATCH already binds the mint pair, price scale, exact fee, and
    // protocol owner; using env fallbacks for any of them would make every proof
    // fail. Tick/min/breaker remain TEE policy, but come from the same governed
    // snapshot. Placeholder-mint loadgen mode is deliberately settlement-disabled.
    let governance_snapshot = if tee_signer_pubkey.is_some() && cfg.governed_market {
        let snapshot = read_governance_snapshot(&cfg)
            .await
            .context("finalized on-chain governance unavailable; refusing real-market startup")?;
        apply_governance_snapshot(&mut match_config, &snapshot);

        let derived_keys = tee_signer_pubkeys
            .as_deref()
            .expect("real signer boot carries the derived key set");
        if !snapshot.authorizes_exact_signer_set(derived_keys) {
            trading_gate.pause();
            tracing::warn!(
                "derived TEE signer set is not the finalized on-chain authorized set; \
                 trading starts PAUSED until governance rotation completes"
            );
        }
        Some(snapshot)
    } else {
        if tee_signer_pubkey.is_some() {
            tracing::warn!(
                "placeholder-mint loadgen mode: finalized MarketConfig is not required and \
                 the on-chain settle pipeline is DISABLED"
            );
        }
        None
    };
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
            "fee_rate_bps > 0 but DARKNYX_TEE_PROTOCOL_OWNER_COMMITMENT is unset — protocol \
             fee notes will mint to a ZERO owner and be UNCLAIMABLE; set the owner \
             commitment, or set DARKNYX_TEE_FEE_RATE_BPS=0"
        );
    }
    // Capture the values the settle driver needs before `match_config`
    // is moved into the matcher driver below ([u8; 32] is Copy).
    let settle_base_mint = match_config.base_mint;
    let settle_quote_mint = match_config.quote_mint;
    let settle_protocol_owner = match_config.protocol_owner_commitment;
    // The finalized fee rate the settle driver feeds the circuit's exact-fee
    // public input — must equal what the matcher charges.
    let settle_fee_rate_bps = match_config.fee_rate_bps as u64;
    let settle_price_scale = match_config.price_scale;
    // Also for the /instruments metadata (captured before the move).
    let market_tick_size = match_config.tick_size;
    let market_min_order_size = match_config.min_order_size;
    let matcher_state = Arc::new(RwLock::new(
        MatcherState::new()
            .with_market(match_config.base_mint, match_config.quote_mint)
            .with_price_scale(match_config.price_scale)
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
        trading_gate: trading_gate.clone(),
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
            "no DARKNYX_TEE_FEED_IDS configured; oracle sync NOT spawned. \
             Matcher ticks will skip (oracle stale) until at least one \
             feed is wired. Set DARKNYX_TEE_FEED_IDS=<hex>,<hex>,... to enable."
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
    // verify → ALT → settle → async close) and finalizes each match only from
    // its own Tx D outcome.
    // Missing any dependency (explicit simulator test mode, prover zkey absent in a
    // local dev run) → enqueue-only, logged below.
    let settle_state = Arc::new(RwLock::new(SettleSchedulerState::default()));
    let settle_driver: Option<SettleDriver> = if !cfg.governed_market {
        None
    } else {
        match settle_signer {
            Some(shard_signers) => {
                // Split the K (keypair, signing_key) pairs into the two parallel
                // Vecs the worker holds (tee_keypairs[j] pairs with signing_keys[j]).
                let (tee_keypairs, signing_keys): (Vec<_>, Vec<_>) =
                    shard_signers.into_iter().unzip();
                let driver = build_settle_driver(
                    &cfg,
                    tee_keypairs,
                    signing_keys,
                    settle_state.clone(),
                    matcher_state.clone(),
                    current_priority_fee.clone(),
                    settle_base_mint,
                    settle_quote_mint,
                    settle_protocol_owner,
                    settle_fee_rate_bps,
                    settle_price_scale,
                    boot_session_id,
                );
                driver
                    .map(|d| {
                        tracing::info!(
                            tee_signer = ?tee_signer_pubkey,
                            "settle driver constructed — live settle pipeline ENABLED"
                        );
                        Some(d)
                    })
                    .unwrap_or_else(|e| {
                        tracing::warn!(
                            error = %e,
                            "settle driver unavailable; scheduler is enqueue-only"
                        );
                        None
                    })
            }
            None => {
                tracing::warn!(
                    "no TEE signer derived (explicit local test mode); settle pipeline disabled"
                );
                None
            }
        }
    };
    let settle_enabled = settle_driver.is_some();
    if cfg.governed_market && tee_signer_pubkey.is_some() && !settle_enabled {
        trading_gate.pause();
        tracing::warn!("governed real-market settle driver is unavailable; trading starts PAUSED");
    }
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
    let instruments = vec![darknyx_tee::api::instruments::InstrumentInfo {
        symbol: cfg.market_symbol.clone(),
        base_mint: settle_base_mint,
        quote_mint: settle_quote_mint,
        tick_size: market_tick_size,
        min_order_size: market_min_order_size,
        oracle_feed_id: cfg.feed_ids.first().cloned().unwrap_or_default(),
    }];
    let api_state = api_state
        .with_matcher_runtime(matcher_state, current_slot, oracle.clone())
        .with_settle_state(settle_state)
        .with_settle_enabled(settle_enabled)
        .with_instruments(instruments);

    let api_state = Arc::new(api_state);

    // U-09: a real-settlement CVM re-reads both governance accounts at finalized
    // commitment every minute. Any RPC/parse failure, parameter drift, disabled
    // market, or signer-set mismatch pauses NEW trading and matching. Cancels and
    // settlement reconciliation keep running. Parameter changes require a restart
    // so every immutable matcher/prover/settler snapshot is adopted atomically;
    // a signer rotation can resume in place once the derived set is authorized.
    let _governance_monitor = match (governance_snapshot, tee_signer_pubkeys) {
        (Some(expected), Some(derived_keys)) => Some(spawn_governance_monitor(
            cfg.clone(),
            expected,
            derived_keys,
            settle_enabled,
            trading_gate,
        )),
        _ => None,
    };

    // ─── 7b. Spawn the Merkle mirror sync (Phase 2b) ──────────────────
    // Cold-boots the mirror from the vault program's history, then
    // live-polls. Uses its OWN read-only RPC client (independent of the
    // settle driver's). Best-effort: a failure here only means /tree/*
    // serves an empty/stale mirror — clients can always read
    // VaultConfig directly. Gated on a real boot (signer present) since
    // explicit simulator test mode has no real cluster to sync against.
    if tee_signer_pubkey.is_some() {
        match SolanaRpcClient::new(&cfg.solana_rpc_url) {
            Ok(rpc) => {
                // One sync over all K shard mirrors; it routes each appended
                // leaf to mirrors[leaf.tree_id] + reconciles each against its
                // MerkleTree[j] shard account.
                let mirrors = api_state.merkle_mirrors.clone();
                // Feed the live `tree` channel of the multiplexed /v1/stream:
                // every newly applied leaf is broadcast here for subscribers.
                let tree_tx = api_state.tree_publisher();
                let vault_program_id = darknyx_tee::settle::vault::vault_program_id();
                let merkle_tree_pdas: Vec<_> = (0..mirrors.len() as u8)
                    .map(|tree_id| darknyx_tee::settle::vault::merkle_tree_pda(tree_id).0)
                    .collect();
                tokio::spawn(async move {
                    let mut sync = MerkleSync::new(
                        rpc,
                        mirrors,
                        vault_program_id,
                        merkle_tree_pdas,
                        MerkleSyncConfig {
                            from_slot: cfg.sync_from_slot,
                            ..MerkleSyncConfig::default()
                        },
                    )
                    .with_tree_publisher(tree_tx);
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
    // congestion. Cap overridable via DARKNYX_TEE_PRIORITY_FEE_CAP.
    if tee_signer_pubkey.is_some() {
        let cap = std::env::var("DARKNYX_TEE_PRIORITY_FEE_CAP")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(darknyx_tee::settle::priority::DEFAULT_PRIORITY_FEE_CAP_MICRO_LAMPORTS);
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
                                let bid = darknyx_tee::settle::priority::priority_fee_bid(
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
    // (the leak guard behind the `fills` channel). No-op only in matcher-less test state.
    darknyx_tee::api::fills_router::spawn_fills_router(api_state.clone());

    // ─── 7e. Spawn the order-lifecycle router ─────────────────────────
    // Fans the matcher's global OrderUpdate broadcast into per-account channels
    // (behind the `orders` channel). No-op only in matcher-less test state.
    darknyx_tee::api::order_router::spawn_order_router(api_state.clone());

    // ─── 8. Build router + bind listener + serve ──────────────────────
    let app = darknyx_tee::api::build_router(api_state);
    let addr: SocketAddr = cfg
        .http_bind
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid DARKNYX_TEE_HTTP_BIND={:?}: {e}", cfg.http_bind))?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(
        local_addr = %listener.local_addr().unwrap_or(addr),
        "darknyx-tee HTTP listening — /health /info /attestation /auth/token /orders"
    );

    axum::serve(listener, app).await?;

    tracing::info!("darknyx-tee exiting");
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_env("DARKNYX_TEE_LOG")
        .unwrap_or_else(|_| EnvFilter::new("info,darknyx_tee=debug"));

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
        .get_key(Some("darknyx/jwt-secret/v2".to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("dstack.get_key('darknyx/jwt-secret/v2') failed: {e}"))?;
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
/// `/circuits/build`; set `DARKNYX_TEE_CIRCUITS_DIR` to point at a local
/// `circuits/build` for dev runs.
#[allow(clippy::too_many_arguments)]
fn build_settle_driver(
    cfg: &darknyx_tee::config::Config,
    tee_keypairs: Vec<solana_keypair::Keypair>,
    signing_keys: Vec<ed25519_dalek::SigningKey>,
    settle_state: Arc<RwLock<SettleSchedulerState>>,
    matcher_state: Arc<RwLock<MatcherState>>,
    current_priority_fee: Arc<AtomicU64>,
    base_mint: [u8; 32],
    quote_mint: [u8; 32],
    protocol_owner_commitment: [u8; 32],
    fee_rate_bps: u64,
    price_scale: u64,
    boot_session_id: [u8; 32],
) -> anyhow::Result<SettleDriver> {
    let rpc = SolanaRpcClient::new(&cfg.solana_rpc_url)?;
    let circuits_dir =
        std::env::var("DARKNYX_TEE_CIRCUITS_DIR").unwrap_or_else(|_| "/circuits/build".to_string());
    // The N=16 proving key is ~74 MB; `read_zkey` parses it
    // synchronously here, before the HTTP surface comes up. Fast in a
    // release build (the CVM), but a plain debug build takes ~minutes —
    // log around it so a slow boot doesn't look hung.
    // Prover backend select (A/B): DARKNYX_TEE_PROVER=rapidsnark (default) | ark.
    // Both backends ship in the image (rapidsnark feature on for the amd64
    // build), so flipping the env A/Bs proving on the SAME image + instance and
    // rolls back instantly without a rebuild/re-attestation. Witness gen is
    // ark-circom either way; only the prove step differs.
    //
    // Default is rapidsnark — it's the CPU baseline we compare the future
    // GPU (ICICLE+rapidsnark) backend against, so it must be the steady-state
    // prover, not an opt-in. The default is feature-gated: a local build
    // without the `rapidsnark` feature (the fast iterate loop) falls back to
    // `ark` so it still boots; the image (built `--features rapidsnark`) gets
    // rapidsnark. An explicit DARKNYX_TEE_PROVER always wins (the A/B lever).
    let default_backend = if cfg!(feature = "rapidsnark") {
        "rapidsnark"
    } else {
        "ark"
    };
    let backend =
        std::env::var("DARKNYX_TEE_PROVER").unwrap_or_else(|_| default_backend.to_string());
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
                    "DARKNYX_TEE_PROVER=rapidsnark but this binary was built without the \
                     `rapidsnark` feature"
                );
            }
        }
        "ark" => Arc::new(
            ArkMatchBatchProver::load(&circuits_dir, PRODUCTION_BATCH_N).map_err(|e| {
                anyhow::anyhow!("load ark N={PRODUCTION_BATCH_N} from {circuits_dir}: {e}")
            })?,
        ),
        "icicle" => {
            #[cfg(feature = "icicle")]
            {
                Arc::new(
                    IcicleMatchBatchProver::load(&circuits_dir, PRODUCTION_BATCH_N).map_err(
                        |e| {
                            anyhow::anyhow!(
                                "load icicle N={PRODUCTION_BATCH_N} from {circuits_dir}: {e}"
                            )
                        },
                    )?,
                )
            }
            #[cfg(not(feature = "icicle"))]
            {
                anyhow::bail!(
                    "DARKNYX_TEE_PROVER=icicle but this binary was built without the `icicle` feature"
                );
            }
        }
        other => anyhow::bail!(
            "unknown DARKNYX_TEE_PROVER={other:?} (expected `ark`, `rapidsnark`, or `icicle`)"
        ),
    };
    tracing::info!(backend, "VALID_MATCH_BATCH proving key loaded");

    // Static settle ALT (vault_config + instructions_sysvar +
    // system_program), created at devnet-setup. When its on-chain
    // address is supplied via DARKNYX_TEE_SETTLE_LOOKUP_TABLE, stack it
    // under the per-batch ALT so the v0 settle tx (Tx D) stays under
    // the 1232-byte cap on the real-mint path. The address list MUST
    // match the on-chain ALT's contents in order — `static_alt_addresses()`
    // mirrors the SDK's `extendLookupTable` order exactly.
    let static_alt = cfg.settle_lookup_table.map(|lut| {
        alt_account(
            solana_address::Address::new_from_array(lut),
            darknyx_tee::settle::settle_batched::static_alt_addresses(cfg.num_trees),
        )
    });
    match &static_alt {
        Some(a) => tracing::info!(alt = %a.key, "static settle ALT threaded into settle worker"),
        None => tracing::warn!(
            "no static settle ALT (DARKNYX_TEE_SETTLE_LOOKUP_TABLE unset) — \
             real-mint settle tx may exceed 1232 bytes"
        ),
    }

    // Per-shard TEE keypairs as Arcs; `[0]` is the PRIMARY (it pays the
    // per-batch verify/ALT/close txs, so it is every marker's `payer`).
    let tee_keypairs = tee_keypairs.into_iter().map(Arc::new).collect::<Vec<_>>();

    // The marker close (Tx E) runs ASYNCHRONOUSLY after marker expiry: the worker
    // enqueues each settled batch's root; this background sweeper reads the
    // on-chain expiry, batches eligible rent-reclaim closes, and replays any
    // unclosed roots from the LUKS volume on restart. It never attempts the old
    // payer early-close path and never blocks the next batch.
    let (marker_sweep_tx, marker_sweep_rx) = tokio::sync::mpsc::unbounded_channel();
    darknyx_tee::settle::spawn_marker_sweeper(
        rpc.clone(),
        tee_keypairs[0].clone(),
        marker_sweep_rx,
        darknyx_tee::persistence::state_dir_from_env(),
        Duration::from_secs(60),
    );
    tracing::info!("marker sweeper spawned (expiry-gated async Tx E close)");

    let ctx = SettleWorkerCtx {
        rpc,
        tee_keypairs,
        signing_keys: signing_keys.into_iter().map(Arc::new).collect(),
        prover,
        static_alt,
        alt_pool: Arc::new(tokio::sync::Mutex::new(
            darknyx_tee::settle::alt_pool::AltPool::new(),
        )),
        settle_state,
        confirm_timeout: Duration::from_secs(60),
        current_priority_fee: current_priority_fee.clone(),
        settle_send_concurrency: cfg.settle_send_concurrency as usize,
        settle_batch_concurrency: cfg.settle_batch_concurrency as usize,
        marker_sweep_tx,
    };

    Ok(SettleDriver {
        ctx,
        matcher_state,
        cfg: SettleDriverConfig {
            boot_session_id,
            base_mint,
            quote_mint,
            protocol_owner_commitment,
            fee_rate_bps,
            price_scale,
            circuit_n: PRODUCTION_BATCH_N,
            settle_batch_concurrency: cfg.settle_batch_concurrency as usize,
        },
    })
}

/// Dev/loadgen `MatchConfig` seed. A governed real-market boot replaces every
/// proof- or policy-relevant value from a finalized on-chain snapshot before
/// the matcher starts. The numbers here are the same ones the litesvm regression
/// tests use, so explicit simulator/loadgen matches reproduce without surprises:
///
///   - `tick_size = 1`            (no per-market tick rounding)
///   - `min_order_size = 0`       (accept any size in dev)
///   - `circuit_breaker_bps`      effectively disabled
///     (`100_000` = 1000% drift band)
///   - `batch_ms = 2000`          (D5 default)
///   - `fee_rate_bps`             from Config (DARKNYX_TEE_FEE_RATE_BPS, default 30)
fn dev_match_config(cfg: &darknyx_tee::config::Config) -> MatchConfig {
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
        price_scale: 100_000_000,
        tick_size: cfg.tick_size,
        min_order_size: cfg.min_order_size,
        circuit_breaker_bps: 100_000,
        batch_ms: 2000,
        // Config clamps to ≤ 10_000, so the u16 cast is lossless.
        fee_rate_bps: cfg.fee_rate_bps as u16,
        protocol_owner_commitment: cfg.protocol_owner_commitment,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GovernanceSnapshot {
    vault: darknyx_tee::solana_rpc::vault_config::OnChainVaultConfig,
    market: darknyx_tee::solana_rpc::market_config::OnChainMarketConfig,
}

impl GovernanceSnapshot {
    fn validate_for_market(
        &self,
        base_mint: &[u8; 32],
        quote_mint: &[u8; 32],
        num_trees: u8,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.vault.fee_rate_bps <= 10_000,
            "VaultConfig fee_rate_bps exceeds 10_000"
        );
        darkpool_crypto::fr_from_be_bytes(&self.vault.protocol_owner_commitment).context(
            "VaultConfig protocol_owner_commitment is not a canonical BN254 field element",
        )?;
        anyhow::ensure!(
            self.vault.fee_rate_bps == 0 || self.vault.protocol_owner_commitment != [0u8; 32],
            "VaultConfig protocol_owner_commitment is zero while fees are enabled"
        );
        anyhow::ensure!(
            self.vault.num_trees == num_trees,
            "VaultConfig num_trees {} does not match DARKNYX_TEE_NUM_TREES {}",
            self.vault.num_trees,
            num_trees
        );
        anyhow::ensure!(
            self.vault.num_tee_keys == self.vault.num_trees,
            "VaultConfig num_tee_keys {} does not equal num_trees {}",
            self.vault.num_tee_keys,
            self.vault.num_trees
        );
        anyhow::ensure!(self.market.enabled, "MarketConfig is disabled");
        anyhow::ensure!(
            self.market.base_mint == *base_mint && self.market.quote_mint == *quote_mint,
            "MarketConfig mint pair does not match configured mints"
        );
        anyhow::ensure!(
            self.market.price_scale > 0,
            "MarketConfig price_scale is zero"
        );
        anyhow::ensure!(self.market.tick_size > 0, "MarketConfig tick_size is zero");
        anyhow::ensure!(
            self.market.min_order_size > 0,
            "MarketConfig min_order_size is zero"
        );
        anyhow::ensure!(
            (1..=10_000).contains(&self.market.circuit_breaker_bps),
            "MarketConfig circuit_breaker_bps is outside 1..=10_000"
        );
        Ok(())
    }

    fn authorizes_exact_signer_set(&self, derived_keys: &[[u8; 32]]) -> bool {
        let active = self.vault.num_tee_keys as usize;
        active == derived_keys.len()
            && self.vault.tee_pubkeys[..active] == derived_keys[..]
            && self.vault.num_trees as usize == derived_keys.len()
    }

    /// Values captured into immutable matcher/prover/settler state. Any drift
    /// requires an atomic process restart rather than a partial hot reload.
    fn runtime_params_match(&self, expected: &Self) -> bool {
        self.vault.protocol_owner_commitment == expected.vault.protocol_owner_commitment
            && self.vault.fee_rate_bps == expected.vault.fee_rate_bps
            && self.vault.num_trees == expected.vault.num_trees
            && self.market == expected.market
    }

    fn permits_trading(
        &self,
        expected: &Self,
        derived_keys: &[[u8; 32]],
        settle_enabled: bool,
    ) -> bool {
        settle_enabled
            && self.runtime_params_match(expected)
            && self.authorizes_exact_signer_set(derived_keys)
    }
}

const GOVERNANCE_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// Read the finalized global VaultConfig account. Missing, wrong-owner, or
/// malformed accounts are returned as `None`; governed boot promotes that to a
/// fatal error and the live monitor promotes it to a trading pause.
async fn read_on_chain_vault_config(
    rpc: &SolanaRpcClient,
) -> Result<
    Option<darknyx_tee::solana_rpc::vault_config::OnChainVaultConfig>,
    darknyx_tee::solana_rpc::RpcError,
> {
    use darknyx_tee::solana_rpc::vault_config as vc;
    let (config_pda, _) = darknyx_tee::settle::vault::vault_config_pda();
    let Some(acc) = rpc.get_account_info(&config_pda).await? else {
        return Ok(None);
    };
    if acc.owner != darknyx_tee::settle::vault::vault_program_id() {
        return Ok(None);
    }
    Ok(vc::parse_vault_config(&acc.data))
}

async fn read_on_chain_market_config(
    cfg: &darknyx_tee::config::Config,
    rpc: &SolanaRpcClient,
) -> Result<
    Option<darknyx_tee::solana_rpc::market_config::OnChainMarketConfig>,
    darknyx_tee::solana_rpc::RpcError,
> {
    use darknyx_tee::settle::vault::{market_config_pda, vault_program_id};
    use darknyx_tee::solana_rpc::market_config::parse_market_config;

    let (market_pda, _) = market_config_pda(&cfg.base_mint, &cfg.quote_mint);
    let Some(account) = rpc.get_account_info(&market_pda).await? else {
        return Ok(None);
    };
    if account.owner != vault_program_id() {
        return Ok(None);
    }
    Ok(parse_market_config(&account.data))
}

async fn read_governance_snapshot(
    cfg: &darknyx_tee::config::Config,
) -> anyhow::Result<GovernanceSnapshot> {
    let rpc = SolanaRpcClient::new(&cfg.solana_rpc_url)?.with_commitment(Commitment::Finalized);
    let vault = read_on_chain_vault_config(&rpc)
        .await?
        .context("VaultConfig missing, wrong-owner, or malformed")?;
    let market = read_on_chain_market_config(cfg, &rpc)
        .await?
        .context("MarketConfig missing, wrong-owner, or malformed")?;

    let snapshot = GovernanceSnapshot { vault, market };
    snapshot.validate_for_market(&cfg.base_mint, &cfg.quote_mint, cfg.num_trees)?;
    Ok(snapshot)
}

fn apply_governance_snapshot(config: &mut MatchConfig, snapshot: &GovernanceSnapshot) {
    if config.fee_rate_bps != snapshot.vault.fee_rate_bps {
        tracing::info!(
            env_value = config.fee_rate_bps,
            on_chain_value = snapshot.vault.fee_rate_bps,
            "adopting finalized VaultConfig fee_rate_bps"
        );
    }
    if config.protocol_owner_commitment != snapshot.vault.protocol_owner_commitment {
        tracing::info!("adopting finalized VaultConfig protocol_owner_commitment");
    }
    config.fee_rate_bps = snapshot.vault.fee_rate_bps;
    config.protocol_owner_commitment = snapshot.vault.protocol_owner_commitment;
    config.base_mint = snapshot.market.base_mint;
    config.quote_mint = snapshot.market.quote_mint;
    adopt_on_chain_param(
        &mut config.price_scale,
        snapshot.market.price_scale,
        "price_scale",
    );
    adopt_on_chain_param(
        &mut config.tick_size,
        snapshot.market.tick_size,
        "tick_size",
    );
    adopt_on_chain_param(
        &mut config.min_order_size,
        snapshot.market.min_order_size,
        "min_order_size",
    );
    adopt_on_chain_param(
        &mut config.circuit_breaker_bps,
        snapshot.market.circuit_breaker_bps,
        "circuit_breaker_bps",
    );
    tracing::info!(
        base_decimals = snapshot.market.base_decimals,
        quote_decimals = snapshot.market.quote_decimals,
        "adopted finalized enabled MarketConfig"
    );
}

fn spawn_governance_monitor(
    cfg: darknyx_tee::config::Config,
    expected: GovernanceSnapshot,
    derived_keys: Vec<[u8; 32]>,
    settle_enabled: bool,
    trading_gate: TradingGate,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(GOVERNANCE_REFRESH_INTERVAL).await;
            match read_governance_snapshot(&cfg).await {
                Ok(current) => {
                    let params_match = current.runtime_params_match(&expected);
                    let signers_match = current.authorizes_exact_signer_set(&derived_keys);
                    if current.permits_trading(&expected, &derived_keys, settle_enabled) {
                        if trading_gate.resume() {
                            tracing::info!(
                                "finalized governance matches the boot snapshot and signer set; \
                                 trading RESUMED"
                            );
                        }
                    } else {
                        let transitioned = trading_gate.pause();
                        tracing::warn!(
                            params_match,
                            signers_match,
                            settle_enabled,
                            newly_paused = transitioned,
                            "finalized governance/runtime mismatch; trading PAUSED (restart after \
                             parameter changes, or complete the signer rotation)"
                        );
                    }
                }
                Err(error) => {
                    let transitioned = trading_gate.pause();
                    tracing::warn!(
                        error = %error,
                        newly_paused = transitioned,
                        "finalized governance refresh failed; trading PAUSED"
                    );
                }
            }
        }
    })
}

/// Adopt a validated on-chain matcher parameter over the boot/env default,
/// logging the override.
fn adopt_on_chain_param(field: &mut u64, on_chain: u64, name: &'static str) {
    if on_chain == *field {
        return;
    }
    tracing::info!(
        param = name,
        env_value = *field,
        on_chain_value = on_chain,
        "adopting on-chain matcher param over env/dev default"
    );
    *field = on_chain;
}

#[cfg(test)]
mod governance_tests {
    use super::*;
    use darknyx_tee::solana_rpc::market_config::OnChainMarketConfig;
    use darknyx_tee::solana_rpc::vault_config::OnChainVaultConfig;

    fn snapshot() -> GovernanceSnapshot {
        let mut tee_pubkeys = [[0u8; 32]; 16];
        tee_pubkeys[0] = [0x11; 32];
        tee_pubkeys[1] = [0x22; 32];
        GovernanceSnapshot {
            vault: OnChainVaultConfig {
                tee_pubkeys,
                protocol_owner_commitment: [0x03; 32],
                fee_rate_bps: 30,
                num_tee_keys: 2,
                num_trees: 2,
            },
            market: OnChainMarketConfig {
                base_mint: [0x04; 32],
                quote_mint: [0x05; 32],
                price_scale: 100_000_000,
                tick_size: 10,
                min_order_size: 1_000,
                circuit_breaker_bps: 500,
                base_decimals: 9,
                quote_decimals: 6,
                enabled: true,
            },
        }
    }

    #[test]
    fn governance_snapshot_separates_runtime_params_from_signer_rotation() {
        let expected = snapshot();
        assert!(expected.authorizes_exact_signer_set(&[[0x11; 32], [0x22; 32]]));

        let mut rotated = expected.clone();
        rotated.vault.tee_pubkeys[1] = [0x33; 32];
        assert!(rotated.runtime_params_match(&expected));
        assert!(!rotated.authorizes_exact_signer_set(&[[0x11; 32], [0x22; 32]]));

        let mut changed = expected.clone();
        changed.vault.fee_rate_bps = 31;
        assert!(!changed.runtime_params_match(&expected));

        assert!(expected.permits_trading(&expected, &[[0x11; 32], [0x22; 32]], true));
        assert!(!expected.permits_trading(&expected, &[[0x11; 32], [0x22; 32]], false));
        assert!(!rotated.permits_trading(&expected, &[[0x11; 32], [0x22; 32]], true));
        assert!(!changed.permits_trading(&expected, &[[0x11; 32], [0x22; 32]], true));
    }

    #[test]
    fn governance_validation_rejects_unsettleable_fee_owner_and_disabled_market() {
        let expected = snapshot();
        assert!(expected
            .validate_for_market(&expected.market.base_mint, &expected.market.quote_mint, 2)
            .is_ok());

        let mut zero_owner_with_fees = expected.clone();
        zero_owner_with_fees.vault.protocol_owner_commitment = [0u8; 32];
        assert!(zero_owner_with_fees
            .validate_for_market(&expected.market.base_mint, &expected.market.quote_mint, 2)
            .unwrap_err()
            .to_string()
            .contains("owner_commitment is zero"));
        zero_owner_with_fees.vault.fee_rate_bps = 0;
        assert!(zero_owner_with_fees
            .validate_for_market(&expected.market.base_mint, &expected.market.quote_mint, 2)
            .is_ok());

        let mut disabled = expected.clone();
        disabled.market.enabled = false;
        assert!(disabled
            .validate_for_market(&expected.market.base_mint, &expected.market.quote_mint, 2)
            .unwrap_err()
            .to_string()
            .contains("disabled"));
    }

    #[test]
    fn finalized_snapshot_overrides_every_immutable_match_parameter() {
        let expected = snapshot();
        let mut config = MatchConfig {
            base_mint: [0; 32],
            quote_mint: [0; 32],
            price_scale: 1,
            tick_size: 1,
            min_order_size: 1,
            circuit_breaker_bps: 1,
            batch_ms: 2_000,
            fee_rate_bps: 0,
            protocol_owner_commitment: [0; 32],
        };
        apply_governance_snapshot(&mut config, &expected);
        assert_eq!(config.base_mint, expected.market.base_mint);
        assert_eq!(config.quote_mint, expected.market.quote_mint);
        assert_eq!(config.price_scale, expected.market.price_scale);
        assert_eq!(config.tick_size, expected.market.tick_size);
        assert_eq!(config.min_order_size, expected.market.min_order_size);
        assert_eq!(
            config.circuit_breaker_bps,
            expected.market.circuit_breaker_bps
        );
        assert_eq!(config.fee_rate_bps, expected.vault.fee_rate_bps);
        assert_eq!(
            config.protocol_owner_commitment,
            expected.vault.protocol_owner_commitment
        );
    }
}
