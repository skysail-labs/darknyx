//! Background tokio task that refreshes the `OracleCache`.
//!
//! At a fixed interval (default 1 s) the task fetches every configured feed in
//! one authenticated Hermes request, verifies the explicitly selected signer
//! and emitter profile, proves every price's Merkle inclusion, enforces signed
//! freshness/replay ordering, and atomically writes the batch into the cache.
//!
//! Lifecycle: spawned at boot (after `keys::derive` runs).
//! Returns a `JoinHandle<()>` the caller can `.abort()` on
//! shutdown.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time;

use crate::matcher::{TradingGate, TradingPauseReason};
use crate::oracle::{
    accumulator,
    cache::{
        convert_pyth_to_market_units, now_ms, CachedPrice, FreshnessPolicy, OracleCache,
        OracleUnits,
    },
    hermes::{HermesBatchUpdate, HermesClient},
    source::OracleSourceKind,
    vaa::{self, TrustProfile},
};

#[derive(Debug, Clone)]
pub struct MarketOracleBinding {
    pub symbol: String,
    pub feed_id: String,
    pub units: OracleUnits,
    /// Exact gate shared with this market's matcher and API route.
    pub trading_gate: TradingGate,
}

#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// Unique feed ids refreshed in one Hermes call.
    pub feed_ids: Vec<String>,
    /// One entry per market. Multiple markets may share one feed while using
    /// different governed decimals/scales.
    pub market_bindings: Vec<MarketOracleBinding>,
    /// Internal verifier selection. Runtime construction pins this to the
    /// upgraded router profile; the legacy value remains only for historical
    /// byte fixtures in unit tests.
    pub trust_profile: TrustProfile,
    pub freshness: FreshnessPolicy,
    /// Refresh cadence. Default 1 s — fast enough that the
    /// matcher's 2 s tick always sees a fresh value, slow enough
    /// that we don't hammer Hermes.
    pub interval: Duration,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            feed_ids: Vec::new(),
            market_bindings: Vec::new(),
            trust_profile: TrustProfile::RouterQuorumV1,
            freshness: FreshnessPolicy {
                max_age_ms: 5_000,
                max_future_skew_ms: 1_000,
            },
            interval: Duration::from_secs(1),
        }
    }
}

fn source_kind(cfg: &SyncConfig) -> OracleSourceKind {
    match cfg.trust_profile {
        TrustProfile::RouterQuorumV1 => OracleSourceKind::PythRouterQuorumV1,
        TrustProfile::LegacyWormholeV1 => OracleSourceKind::DebugFixtureV1,
    }
}

/// Spawn the background sync task. Returns the JoinHandle so main
/// can abort it on shutdown. Caller-owned: never drops on its own.
pub fn spawn_oracle_sync(
    cache: OracleCache,
    client: HermesClient,
    cfg: SyncConfig,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        // Feed ids are immutable deployment configuration. Decode and
        // normalize them once, rather than rebuilding the lookup on every
        // one-second refresh cycle (PF-17).
        let requested = match requested_feed_map(&cfg.feed_ids) {
            Ok(requested) => requested,
            Err(error) => {
                for binding in &cfg.market_bindings {
                    binding.trading_gate.pause_for(TradingPauseReason::Oracle);
                }
                tracing::error!(error = %error, "oracle sync configuration invalid; markets PAUSED");
                return;
            }
        };
        let mut ticker = time::interval(cfg.interval);
        // Make the first tick fire immediately so the cache is
        // warm before the matching loop starts.
        ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let started = Instant::now();
            match refresh_batch_prepared(&client, &cache, &cfg, &requested).await {
                Ok((accepted, replayed)) => {
                    reconcile_market_health(
                        &cache,
                        &cfg.market_bindings,
                        cfg.freshness,
                        source_kind(&cfg),
                    )
                    .await;
                    tracing::debug!(
                        source = source_kind(&cfg).as_str(),
                        feed_count = cfg.feed_ids.len(),
                        hermes_requests = 1,
                        accepted,
                        replayed,
                        refresh_ms = started.elapsed().as_millis() as u64,
                        "oracle sync: batch refresh complete"
                    );
                }
                Err(batch_error) => {
                    tracing::warn!(
                        source = source_kind(&cfg).as_str(),
                        feed_count = cfg.feed_ids.len(),
                        refresh_ms = started.elapsed().as_millis() as u64,
                        error = %batch_error,
                        "oracle sync: batch refresh failed; retrying each feed independently"
                    );
                    // Normal operation remains one authenticated request. The
                    // per-feed path is only for failures: it prevents one
                    // missing, malformed, or unauthenticated feed from starving
                    // every other market's cache while preserving fail-closed
                    // behavior for the affected feed. Run these requests
                    // concurrently so one 5 s timeout cannot serially hold up
                    // every healthy market (the configured feed count is
                    // already boot-bounded).
                    let mut refreshes = JoinSet::new();
                    for feed_id in &cfg.feed_ids {
                        let feed_cfg = config_for_feed(&cfg, feed_id);
                        let client = client.clone();
                        let cache = cache.clone();
                        let feed_id = feed_id.clone();
                        refreshes.spawn(async move {
                            let result = refresh_batch(&client, &cache, &feed_cfg).await;
                            (feed_id, feed_cfg, result)
                        });
                    }
                    while let Some(joined) = refreshes.join_next().await {
                        let Ok((feed_id, feed_cfg, result)) = joined else {
                            // A task panic/cancellation is an internal sync
                            // failure rather than an attributable feed failure.
                            // Fail closed across the venue; the next normal
                            // cycle can recover each market independently.
                            reconcile_market_health(
                                &cache,
                                &cfg.market_bindings,
                                cfg.freshness,
                                source_kind(&cfg),
                            )
                            .await;
                            tracing::error!(
                                source = source_kind(&cfg).as_str(),
                                "oracle sync: isolated refresh task failed; retaining verified cache while fresh"
                            );
                            continue;
                        };
                        match result {
                            Ok((accepted, replayed)) => {
                                reconcile_market_health(
                                    &cache,
                                    &feed_cfg.market_bindings,
                                    feed_cfg.freshness,
                                    source_kind(&feed_cfg),
                                )
                                .await;
                                tracing::debug!(
                                    source = source_kind(&feed_cfg).as_str(),
                                    feed_id = feed_id,
                                    accepted,
                                    replayed,
                                    "oracle sync: isolated feed refresh recovered"
                                );
                            }
                            Err(error) => {
                                reconcile_market_health(
                                    &cache,
                                    &feed_cfg.market_bindings,
                                    feed_cfg.freshness,
                                    source_kind(&feed_cfg),
                                )
                                .await;
                                tracing::warn!(
                                    source = source_kind(&feed_cfg).as_str(),
                                    feed_id = feed_id,
                                    error = %error,
                                    "oracle sync: isolated feed refresh failed; retaining verified cache while fresh"
                                );
                            }
                        }
                    }
                }
            }
        }
    })
}

fn config_for_feed(cfg: &SyncConfig, feed_id: &str) -> SyncConfig {
    SyncConfig {
        feed_ids: vec![feed_id.to_string()],
        market_bindings: cfg
            .market_bindings
            .iter()
            .filter(|binding| binding.feed_id.eq_ignore_ascii_case(feed_id))
            .cloned()
            .collect(),
        trust_profile: cfg.trust_profile,
        freshness: cfg.freshness,
        interval: cfg.interval,
    }
}

pub(crate) async fn reconcile_market_health(
    cache: &OracleCache,
    bindings: &[MarketOracleBinding],
    freshness: FreshnessPolicy,
    source: OracleSourceKind,
) {
    for binding in bindings {
        match cache
            .snapshot(&binding.feed_id, freshness, binding.units)
            .await
        {
            Ok(_) => {
                let was_paused = binding
                    .trading_gate
                    .is_paused_for(TradingPauseReason::Oracle);
                binding.trading_gate.resume_for(TradingPauseReason::Oracle);
                if was_paused {
                    tracing::info!(
                        symbol = binding.symbol,
                        feed_id = binding.feed_id,
                        source = source.as_str(),
                        "oracle trust/freshness recovered; market trading RESUMED"
                    );
                }
            }
            Err(error) => {
                let transitioned = binding.trading_gate.pause_for(TradingPauseReason::Oracle);
                tracing::warn!(
                    symbol = binding.symbol,
                    feed_id = binding.feed_id,
                    newly_paused = transitioned,
                    error = %error,
                    "oracle sync: market snapshot unhealthy; market trading PAUSED"
                );
            }
        }
    }
}

/// One all-or-nothing refresh cycle.
async fn refresh_batch(
    client: &HermesClient,
    cache: &OracleCache,
    cfg: &SyncConfig,
) -> anyhow::Result<(usize, usize)> {
    let requested = requested_feed_map(&cfg.feed_ids)?;
    refresh_batch_prepared(client, cache, cfg, &requested).await
}

async fn refresh_batch_prepared(
    client: &HermesClient,
    cache: &OracleCache,
    cfg: &SyncConfig,
    requested: &HashMap<[u8; 32], String>,
) -> anyhow::Result<(usize, usize)> {
    anyhow::ensure!(!cfg.feed_ids.is_empty(), "oracle feed set is empty");
    let update = client.fetch_many(&cfg.feed_ids).await?;
    apply_batch_update_at_prepared(cache, cfg, requested, update, now_ms()).await
}

#[cfg(test)]
async fn apply_batch_update_at(
    cache: &OracleCache,
    cfg: &SyncConfig,
    update: HermesBatchUpdate,
    observed_at_ms: u64,
) -> anyhow::Result<(usize, usize)> {
    let requested = requested_feed_map(&cfg.feed_ids)?;
    apply_batch_update_at_prepared(cache, cfg, &requested, update, observed_at_ms).await
}

fn requested_feed_map(feed_ids: &[String]) -> anyhow::Result<HashMap<[u8; 32], String>> {
    feed_ids
        .iter()
        .map(|feed_id| {
            let bytes: [u8; 32] = hex::decode(feed_id)
                .ok()
                .and_then(|value| value.try_into().ok())
                .ok_or_else(|| anyhow::anyhow!("feed id {feed_id} is not 32 hex bytes"))?;
            Ok((bytes, feed_id.to_ascii_lowercase()))
        })
        .collect()
}

async fn apply_batch_update_at_prepared(
    cache: &OracleCache,
    cfg: &SyncConfig,
    requested: &HashMap<[u8; 32], String>,
    update: HermesBatchUpdate,
    observed_at_ms: u64,
) -> anyhow::Result<(usize, usize)> {
    // 1. Parse the raw AccumulatorUpdateData (PNAU) envelope → VAA + updates.
    let parsed = accumulator::parse(&update.accumulator)
        .map_err(|e| anyhow::anyhow!("accumulator parse failed: {e}"))?;

    // 2. Verify the complete deployment-selected profile. Never infer signer
    //    set/quorum from the VAA itself.
    let verified_vaa = vaa::verify_for_profile(parsed.vaa, cfg.trust_profile)?;

    // 3. Extract the Merkle root from the *guardian-verified* VAA payload. This
    //    root — and ONLY this root — is bound by the guardian signatures.
    let root = accumulator::merkle_root_from_vaa_payload(verified_vaa.payload)
        .map_err(|e| anyhow::anyhow!("Pyth merkle root parse failed: {e}"))?;

    let mut found = HashMap::<String, accumulator::PriceFeedMessage>::new();
    for pu in &parsed.updates {
        let msg = match accumulator::parse_price_feed_message(pu.message) {
            Ok(m) => m,
            // Non-PriceFeedMessage discriminants (e.g. TWAP) — skip, not our
            // concern for this feed.
            Err(accumulator::AccumulatorError::NotPriceFeedMessage { .. }) => continue,
            Err(e) => return Err(anyhow::anyhow!("price message decode failed: {e}")),
        };
        let Some(feed_id) = requested.get(&msg.feed_id) else {
            continue;
        };
        if !accumulator::verify_inclusion(pu.message, &pu.proof, &root) {
            return Err(anyhow::anyhow!(
                accumulator::AccumulatorError::InclusionFailed {
                    feed_id: feed_id.clone(),
                    recomputed: accumulator::compute_root(pu.message, &pu.proof),
                    attested: root,
                }
            ));
        }
        if found.insert(feed_id.clone(), msg).is_some() {
            anyhow::bail!("accumulator contains duplicate price message for {feed_id}");
        }
    }
    for feed_id in &cfg.feed_ids {
        if !found.contains_key(&feed_id.to_ascii_lowercase()) {
            return Err(anyhow::anyhow!(
                accumulator::AccumulatorError::FeedNotFound {
                    feed_id: feed_id.clone(),
                }
            ));
        }
    }

    // 5. Validate every binary-proven value, cross-check untrusted JSON, and
    //    prove every configured market unit conversion is representable before
    //    any cache entry changes.
    let mut units_by_feed = HashMap::<String, HashSet<OracleUnits>>::new();
    for binding in &cfg.market_bindings {
        units_by_feed
            .entry(binding.feed_id.to_ascii_lowercase())
            .or_default()
            .insert(binding.units);
    }
    let mut entries = Vec::with_capacity(cfg.feed_ids.len());
    for feed_id in &cfg.feed_ids {
        let normalized = feed_id.to_ascii_lowercase();
        let msg = found[&normalized];
        if msg.ema_price <= 0 || msg.publish_time < 0 {
            anyhow::bail!(
                "binary-proven Pyth value invalid for {normalized}: ema_price={} publish_time={}",
                msg.ema_price,
                msg.publish_time
            );
        }
        let ema_price = msg.ema_price as u64;
        let publish_time_ms = (msg.publish_time as u64)
            .checked_mul(1000)
            .ok_or_else(|| anyhow::anyhow!("publish time overflow for {normalized}"))?;
        let json = update
            .prices
            .get(&normalized)
            .ok_or_else(|| anyhow::anyhow!("Hermes JSON missing requested feed {normalized}"))?;
        if ema_price != json.json_ema_price
            || msg.exponent != json.json_exponent
            || publish_time_ms != json.json_publish_time_ms
        {
            anyhow::bail!(
                "Hermes JSON/binary mismatch for {normalized}: binary ema={ema_price} \
                 expo={} publish_ms={publish_time_ms} vs json ema={} expo={} publish_ms={}",
                msg.exponent,
                json.json_ema_price,
                json.json_exponent,
                json.json_publish_time_ms,
            );
        }
        let unit_targets = units_by_feed
            .get(&normalized)
            .ok_or_else(|| anyhow::anyhow!("no governed unit binding for feed {normalized}"))?;
        for units in unit_targets {
            convert_pyth_to_market_units(ema_price, msg.exponent, *units, true)?;
            convert_pyth_to_market_units(msg.ema_conf, msg.exponent, *units, false)?;
        }
        entries.push((
            normalized,
            CachedPrice {
                twap: ema_price,
                confidence: msg.ema_conf,
                exponent: msg.exponent,
                publish_time_ms,
                source_sequence: verified_vaa.sequence,
                source: source_kind(cfg),
                last_updated_ms: 0,
                evidence: parsed.vaa.to_vec(),
            },
        ));
    }

    let report = cache
        .apply_verified_batch_at(entries, cfg.freshness, observed_at_ms)
        .await?;
    Ok((report.accepted, report.replayed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oracle::hermes::HermesPriceUpdate;
    use axum::{
        extract::{RawQuery, State},
        http::StatusCode,
        routing::get,
        Json, Router,
    };
    use serde_json::{json, Value};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio::sync::Notify;

    const FEED: &str = "ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d";
    const OTHER_FEED: &str = "aa0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d";
    const FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/sol_usd_accumulator.bin");

    fn config() -> SyncConfig {
        let gate = TradingGate::default();
        SyncConfig {
            feed_ids: vec![FEED.into()],
            market_bindings: vec![MarketOracleBinding {
                symbol: "SOL-USDC".to_string(),
                feed_id: FEED.into(),
                units: OracleUnits {
                    base_decimals: 6,
                    quote_decimals: 6,
                    price_scale: 100_000_000,
                },
                trading_gate: gate,
            }],
            trust_profile: TrustProfile::LegacyWormholeV1,
            freshness: FreshnessPolicy {
                max_age_ms: 5_000,
                max_future_skew_ms: 1_000,
            },
            interval: Duration::from_secs(1),
        }
    }

    fn fixture_message() -> accumulator::PriceFeedMessage {
        let parsed = accumulator::parse(FIXTURE).unwrap();
        accumulator::parse_price_feed_message(parsed.updates[0].message).unwrap()
    }

    fn batch(json_ema_price: u64) -> HermesBatchUpdate {
        let message = fixture_message();
        HermesBatchUpdate {
            accumulator: FIXTURE.to_vec(),
            prices: HashMap::from([(
                FEED.into(),
                HermesPriceUpdate {
                    feed_id: FEED.into(),
                    json_ema_price,
                    json_exponent: message.exponent,
                    json_publish_time_ms: (message.publish_time as u64) * 1_000,
                },
            )]),
        }
    }

    fn fixture_publish_ms() -> u64 {
        (fixture_message().publish_time as u64) * 1_000
    }

    #[derive(Clone)]
    struct HermesStub {
        good_response: Value,
        batch_requests: Arc<AtomicUsize>,
        good_requests: Arc<AtomicUsize>,
        bad_requests: Arc<AtomicUsize>,
        release_bad: Arc<Notify>,
    }

    async fn isolated_hermes_stub(
        State(stub): State<HermesStub>,
        RawQuery(query): RawQuery,
    ) -> (StatusCode, Json<Value>) {
        let query = query.unwrap_or_default();
        let asks_for_good = query.contains(FEED);
        let asks_for_bad = query.contains(OTHER_FEED);
        match (asks_for_good, asks_for_bad) {
            (true, true) => {
                stub.batch_requests.fetch_add(1, Ordering::SeqCst);
                (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({"error":"one feed unavailable"})),
                )
            }
            (true, false) => {
                stub.good_requests.fetch_add(1, Ordering::SeqCst);
                (StatusCode::OK, Json(stub.good_response))
            }
            (false, true) => {
                stub.bad_requests.fetch_add(1, Ordering::SeqCst);
                // Hold the failed feed open until the test observes that the
                // healthy feed already resumed. A serial fallback deadlocks
                // here and makes the assertion time out.
                stub.release_bad.notified().await;
                (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({"error":"feed unavailable"})),
                )
            }
            (false, false) => (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":"unexpected query"})),
            ),
        }
    }

    #[tokio::test]
    async fn verified_fixture_reaches_cache_with_signed_time_and_market_units() {
        let cache = OracleCache::new();
        let published = fixture_publish_ms();
        let result =
            apply_batch_update_at(&cache, &config(), batch(7_471_749_900), published + 100)
                .await
                .unwrap();
        assert_eq!(result, (1, 0));
        let cfg = config();
        let snapshot = cache
            .snapshot_at(
                FEED,
                cfg.freshness,
                cfg.market_bindings[0].units,
                published + 200,
            )
            .await
            .unwrap();
        assert_eq!(snapshot.twap, 7_471_749_900);
        assert_eq!(snapshot.publish_time_ms, published);
    }

    #[tokio::test]
    async fn json_split_or_signed_staleness_cannot_partially_update_cache() {
        let published = fixture_publish_ms();

        let mismatch_cache = OracleCache::new();
        let mismatch = apply_batch_update_at(
            &mismatch_cache,
            &config(),
            batch(7_471_749_901),
            published + 100,
        )
        .await
        .expect_err("untrusted JSON must match the included binary value");
        assert!(mismatch.to_string().contains("JSON/binary mismatch"));
        assert_eq!(mismatch_cache.feed_count().await, 0);

        let stale_cache = OracleCache::new();
        let stale = apply_batch_update_at(
            &stale_cache,
            &config(),
            batch(7_471_749_900),
            published + 5_001,
        )
        .await
        .expect_err("signed staleness must reject the whole refresh");
        assert!(stale.to_string().contains("stale"));
        assert_eq!(stale_cache.feed_count().await, 0);
    }

    #[tokio::test]
    async fn market_health_and_feed_failures_are_isolated() {
        let sol_gate = TradingGate::default();
        let btc_gate = sol_gate.fork_market();
        sol_gate.pause_for(TradingPauseReason::Oracle);
        btc_gate.pause_for(TradingPauseReason::Oracle);
        let units = OracleUnits {
            base_decimals: 6,
            quote_decimals: 6,
            price_scale: 100_000_000,
        };
        let cfg = SyncConfig {
            feed_ids: vec![FEED.into(), OTHER_FEED.into()],
            market_bindings: vec![
                MarketOracleBinding {
                    symbol: "SOL-USDC".to_string(),
                    feed_id: FEED.into(),
                    units,
                    trading_gate: sol_gate.clone(),
                },
                MarketOracleBinding {
                    symbol: "BTC-USDC".to_string(),
                    feed_id: OTHER_FEED.into(),
                    units,
                    trading_gate: btc_gate.clone(),
                },
            ],
            ..SyncConfig::default()
        };
        let cache = OracleCache::new();
        cache
            .seed_unverified(
                OTHER_FEED.to_string(),
                CachedPrice {
                    twap: 7_471_749_900,
                    confidence: 0,
                    exponent: -8,
                    publish_time_ms: 0,
                    source_sequence: 1,
                    source: OracleSourceKind::DebugFixtureV1,
                    last_updated_ms: 0,
                    evidence: Vec::new(),
                },
            )
            .await;

        reconcile_market_health(
            &cache,
            &cfg.market_bindings,
            cfg.freshness,
            source_kind(&cfg),
        )
        .await;
        assert!(
            sol_gate.is_paused_for(TradingPauseReason::Oracle),
            "missing SOL feed remains fail-closed"
        );
        assert!(
            btc_gate.is_open(),
            "fresh BTC feed resumes only the BTC market"
        );

        assert!(btc_gate.is_open(), "a failed peer feed must not pause BTC");

        let sol_only = config_for_feed(&cfg, FEED);
        assert_eq!(sol_only.feed_ids, vec![FEED.to_string()]);
        assert_eq!(sol_only.market_bindings.len(), 1);
        assert_eq!(sol_only.market_bindings[0].symbol, "SOL-USDC");
    }

    #[tokio::test]
    async fn failed_batch_retries_feeds_concurrently_and_resumes_only_the_healthy_market() {
        let message = fixture_message();
        let stub = HermesStub {
            good_response: json!({
                "binary": {
                    "encoding": "hex",
                    "data": [hex::encode(FIXTURE)],
                },
                "parsed": [{
                    "id": FEED,
                    "ema_price": {
                        "price": message.ema_price.to_string(),
                        "expo": message.exponent,
                        "publish_time": message.publish_time,
                    },
                }],
            }),
            batch_requests: Arc::new(AtomicUsize::new(0)),
            good_requests: Arc::new(AtomicUsize::new(0)),
            bad_requests: Arc::new(AtomicUsize::new(0)),
            release_bad: Arc::new(Notify::new()),
        };
        let app = Router::new()
            .route("/v2/updates/price/latest", get(isolated_hermes_stub))
            .with_state(stub.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let sol_gate = TradingGate::default();
        let btc_gate = sol_gate.fork_market();
        sol_gate.pause_for(TradingPauseReason::Oracle);
        btc_gate.pause_for(TradingPauseReason::Oracle);
        let units = OracleUnits {
            base_decimals: 6,
            quote_decimals: 6,
            price_scale: 100_000_000,
        };
        let sync = spawn_oracle_sync(
            OracleCache::new(),
            HermesClient::with_endpoint(&endpoint).unwrap(),
            SyncConfig {
                feed_ids: vec![FEED.into(), OTHER_FEED.into()],
                market_bindings: vec![
                    MarketOracleBinding {
                        symbol: "SOL-USDC".to_string(),
                        feed_id: FEED.into(),
                        units,
                        trading_gate: sol_gate.clone(),
                    },
                    MarketOracleBinding {
                        symbol: "BTC-USDC".to_string(),
                        feed_id: OTHER_FEED.into(),
                        units,
                        trading_gate: btc_gate.clone(),
                    },
                ],
                trust_profile: TrustProfile::LegacyWormholeV1,
                freshness: FreshnessPolicy {
                    // The signed fixture is intentionally historical. This test
                    // exercises request/failure isolation, while the freshness
                    // boundary has its own fixed-time tests above.
                    max_age_ms: u64::MAX,
                    max_future_skew_ms: 1_000,
                },
                interval: Duration::from_secs(3_600),
            },
        );

        time::timeout(Duration::from_secs(2), async {
            while !sol_gate.is_open() || stub.bad_requests.load(Ordering::SeqCst) != 1 {
                time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("healthy market should resume without waiting for failed feed");
        assert!(
            btc_gate.is_paused_for(TradingPauseReason::Oracle),
            "failed feed's market remains paused"
        );
        assert_eq!(stub.batch_requests.load(Ordering::SeqCst), 1);
        assert_eq!(stub.good_requests.load(Ordering::SeqCst), 1);
        assert_eq!(stub.bad_requests.load(Ordering::SeqCst), 1);

        stub.release_bad.notify_one();
        sync.abort();
        server.abort();
    }
}
