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
use tokio::task::JoinHandle;
use tokio::time;

use crate::matcher::{TradingGate, TradingPauseReason};
use crate::oracle::{
    accumulator,
    cache::{
        convert_pyth_to_market_units, now_ms, CachedPrice, FreshnessPolicy, OracleCache,
        OracleUnits,
    },
    hermes::{HermesBatchUpdate, HermesClient},
    vaa::{self, TrustProfile},
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MarketOracleBinding {
    pub feed_id: String,
    pub units: OracleUnits,
}

#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// Unique feed ids refreshed in one Hermes call.
    pub feed_ids: Vec<String>,
    /// One entry per market. Multiple markets may share one feed while using
    /// different governed decimals/scales.
    pub market_bindings: Vec<MarketOracleBinding>,
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
            trust_profile: TrustProfile::LegacyWormholeV1,
            freshness: FreshnessPolicy {
                max_age_ms: 5_000,
                max_future_skew_ms: 1_000,
            },
            interval: Duration::from_secs(1),
        }
    }
}

/// Spawn the background sync task. Returns the JoinHandle so main
/// can abort it on shutdown. Caller-owned: never drops on its own.
pub fn spawn_oracle_sync(
    cache: OracleCache,
    client: HermesClient,
    cfg: SyncConfig,
    trading_gate: TradingGate,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = time::interval(cfg.interval);
        // Make the first tick fire immediately so the cache is
        // warm before the matching loop starts.
        ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let started = Instant::now();
            match refresh_batch(&client, &cache, &cfg).await {
                Ok((accepted, replayed)) => {
                    let mut healthy = true;
                    for binding in &cfg.market_bindings {
                        if let Err(error) = cache
                            .snapshot(&binding.feed_id, cfg.freshness, binding.units)
                            .await
                        {
                            healthy = false;
                            tracing::warn!(
                                feed_id = binding.feed_id,
                                error = %error,
                                "oracle sync: post-refresh market snapshot unhealthy"
                            );
                            break;
                        }
                    }
                    if healthy {
                        if trading_gate.resume_for(TradingPauseReason::Oracle) {
                            tracing::info!(
                                profile = cfg.trust_profile.as_str(),
                                "oracle trust/freshness recovered; trading RESUMED"
                            );
                        }
                    } else {
                        trading_gate.pause_for(TradingPauseReason::Oracle);
                    }
                    tracing::debug!(
                        profile = cfg.trust_profile.as_str(),
                        feed_count = cfg.feed_ids.len(),
                        hermes_requests = 1,
                        accepted,
                        replayed,
                        refresh_ms = started.elapsed().as_millis() as u64,
                        "oracle sync: batch refresh complete"
                    );
                }
                Err(error) => {
                    let transitioned = trading_gate.pause_for(TradingPauseReason::Oracle);
                    tracing::warn!(
                        profile = cfg.trust_profile.as_str(),
                        feed_count = cfg.feed_ids.len(),
                        refresh_ms = started.elapsed().as_millis() as u64,
                        newly_paused = transitioned,
                        error = %error,
                        "oracle sync: batch refresh failed; trading PAUSED"
                    );
                }
            }
        }
    })
}

/// One all-or-nothing refresh cycle.
async fn refresh_batch(
    client: &HermesClient,
    cache: &OracleCache,
    cfg: &SyncConfig,
) -> anyhow::Result<(usize, usize)> {
    anyhow::ensure!(!cfg.feed_ids.is_empty(), "oracle feed set is empty");
    let update = client.fetch_many(&cfg.feed_ids).await?;
    apply_batch_update_at(cache, cfg, update, now_ms()).await
}

async fn apply_batch_update_at(
    cache: &OracleCache,
    cfg: &SyncConfig,
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

    let requested = cfg
        .feed_ids
        .iter()
        .map(|feed_id| {
            let bytes: [u8; 32] = hex::decode(feed_id)
                .ok()
                .and_then(|value| value.try_into().ok())
                .ok_or_else(|| anyhow::anyhow!("feed id {feed_id} is not 32 hex bytes"))?;
            Ok((bytes, feed_id.to_ascii_lowercase()))
        })
        .collect::<anyhow::Result<HashMap<_, _>>>()?;
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
                vaa_sequence: verified_vaa.sequence,
                trust_profile: cfg.trust_profile,
                last_updated_ms: 0,
                vaa: parsed.vaa.to_vec(),
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

    const FEED: &str = "ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d";
    const FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/sol_usd_accumulator.bin");

    fn config() -> SyncConfig {
        SyncConfig {
            feed_ids: vec![FEED.into()],
            market_bindings: vec![MarketOracleBinding {
                feed_id: FEED.into(),
                units: OracleUnits {
                    base_decimals: 6,
                    quote_decimals: 6,
                    price_scale: 100_000_000,
                },
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
}
