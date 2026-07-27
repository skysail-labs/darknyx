//! Concurrent oracle-price cache. The `sync` task writes; the
//! matcher tick reads. `tokio::sync::RwLock` so readers don't
//! block each other and the write window is microseconds.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::RwLock;

use super::vaa::TrustProfile;

/// Identifier for a Pyth price feed. Hex-encoded 32-byte feed id
/// from <https://pyth.network/developers/price-feed-ids>. E.g.
/// SOL/USD on mainnet:
/// `ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d`.
pub type FeedId = String;

/// One cached price entry.
#[derive(Debug, Clone)]
pub struct CachedPrice {
    /// Most-recent EMA price (TWAP proxy), Pyth-native fixed point
    /// per `exponent`. Always positive; the sync task rejects
    /// non-positive Pyth prices before insertion.
    pub twap: u64,
    /// Pyth confidence interval, same units as `twap`.
    pub confidence: u64,
    /// Pyth exponent (power of 10). Consumed at the cache boundary to convert
    /// the mantissa into each market's governed atomic units.
    pub exponent: i32,
    /// Pyth-reported publish time, milliseconds since UNIX epoch.
    pub publish_time_ms: u64,
    /// Signed VAA sequence. It must increase when `publish_time_ms` increases;
    /// exact replays never refresh local arrival health.
    pub vaa_sequence: u64,
    /// Explicit signer/emitter profile that authenticated this update.
    pub trust_profile: TrustProfile,
    /// UNIX epoch milliseconds when this process accepted the update. Used
    /// alongside signed publish time: a healthy local fetch loop cannot make
    /// an old signed update fresh.
    pub last_updated_ms: u64,
    /// Raw VAA bytes that backed this update. Kept for the
    /// future v3 path where the on-chain `verify_match_batch`
    /// re-verifies Pyth signatures directly.
    pub vaa: Vec<u8>,
}

/// `OracleSnapshot` is what the matcher tick consumes — same shape
/// the `darkpool_matcher::OracleSnapshot` type expects. We mirror
/// the field set here for clarity; conversion into the matcher type lives
/// alongside the matcher integration.
#[derive(Debug, Clone)]
pub struct OracleSnapshot {
    pub twap: u64,
    pub confidence: u64,
    /// Signed Pyth publish time and the local observation time used by the
    /// pure matcher to enforce the same freshness contract defensively.
    pub publish_time_ms: u64,
    pub observed_at_ms: u64,
    pub max_age_ms: u64,
    pub max_future_skew_ms: u64,
}

/// Conversion target for one governed market. `twap` handed to the matcher is
/// in atomic quote units per atomic base unit, fixed-point by `price_scale`.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct OracleUnits {
    pub base_decimals: u8,
    pub quote_decimals: u8,
    pub price_scale: u64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct FreshnessPolicy {
    pub max_age_ms: u64,
    pub max_future_skew_ms: u64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct BatchApplyReport {
    pub accepted: usize,
    pub replayed: usize,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum OracleCacheError {
    #[error("oracle batch contains duplicate feed {0}")]
    DuplicateFeed(String),
    #[error(
        "oracle update for {feed_id} is stale: publish_time_ms={publish_time_ms}, \
         now_ms={now_ms}, max_age_ms={max_age_ms}"
    )]
    SignedStale {
        feed_id: String,
        publish_time_ms: u64,
        now_ms: u64,
        max_age_ms: u64,
    },
    #[error(
        "oracle update for {feed_id} is too far in the future: \
         publish_time_ms={publish_time_ms}, now_ms={now_ms}, \
         max_future_skew_ms={max_future_skew_ms}"
    )]
    FutureDated {
        feed_id: String,
        publish_time_ms: u64,
        now_ms: u64,
        max_future_skew_ms: u64,
    },
    #[error(
        "oracle update for {feed_id} moved backwards: previous publish/sequence \
         {previous_publish_time_ms}/{previous_sequence}, new {publish_time_ms}/{sequence}"
    )]
    NonMonotonic {
        feed_id: String,
        previous_publish_time_ms: u64,
        previous_sequence: u64,
        publish_time_ms: u64,
        sequence: u64,
    },
    #[error("oracle replay for {feed_id} changed authenticated price fields")]
    ConflictingReplay { feed_id: String },
    #[error("oracle feed {0} is missing")]
    Missing(String),
    #[error(
        "oracle feed {feed_id} local arrival is stale: age_ms={age_ms}, max_age_ms={max_age_ms}"
    )]
    LocalStale {
        feed_id: String,
        age_ms: u64,
        max_age_ms: u64,
    },
    #[error(transparent)]
    Units(#[from] UnitConversionError),
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum UnitConversionError {
    #[error("oracle price scale must be non-zero")]
    ZeroPriceScale,
    #[error("oracle decimal exponent {decimal_exponent} is outside checked power-of-ten range")]
    ExponentOutOfRange { decimal_exponent: i32 },
    #[error("oracle unit conversion overflowed u128")]
    IntermediateOverflow,
    #[error("positive oracle value rounded below one market price unit")]
    Underflow,
    #[error("oracle unit conversion result {0} exceeds u64")]
    OutputOverflow(u128),
}

#[derive(Clone, Default)]
pub struct OracleCache {
    inner: Arc<RwLock<HashMap<FeedId, CachedPrice>>>,
}

impl OracleCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Atomically validate and apply a verified multi-feed update. Stale,
    /// future-dated, out-of-order, and conflicting replay batches leave the
    /// entire cache unchanged. An exact replay is recognized but deliberately
    /// does not refresh `last_updated_ms`.
    pub async fn apply_verified_batch(
        &self,
        entries: Vec<(FeedId, CachedPrice)>,
        policy: FreshnessPolicy,
    ) -> Result<BatchApplyReport, OracleCacheError> {
        self.apply_verified_batch_at(entries, policy, now_ms())
            .await
    }

    pub async fn apply_verified_batch_at(
        &self,
        mut entries: Vec<(FeedId, CachedPrice)>,
        policy: FreshnessPolicy,
        observed_at_ms: u64,
    ) -> Result<BatchApplyReport, OracleCacheError> {
        let mut seen = HashSet::with_capacity(entries.len());
        for (feed_id, entry) in &entries {
            if !seen.insert(feed_id.clone()) {
                return Err(OracleCacheError::DuplicateFeed(feed_id.clone()));
            }
            validate_signed_freshness(feed_id, entry, policy, observed_at_ms)?;
        }

        let mut guard = self.inner.write().await;
        let mut replayed = 0usize;
        for (feed_id, entry) in &entries {
            let Some(previous) = guard.get(feed_id) else {
                continue;
            };
            if entry.publish_time_ms < previous.publish_time_ms
                || entry.vaa_sequence < previous.vaa_sequence
                || (entry.publish_time_ms > previous.publish_time_ms
                    && entry.vaa_sequence <= previous.vaa_sequence)
            {
                return Err(OracleCacheError::NonMonotonic {
                    feed_id: feed_id.clone(),
                    previous_publish_time_ms: previous.publish_time_ms,
                    previous_sequence: previous.vaa_sequence,
                    publish_time_ms: entry.publish_time_ms,
                    sequence: entry.vaa_sequence,
                });
            }
            // `(publish_time_ms, vaa_sequence)` identifies the message. Two
            // payloads carrying that SAME pair but different authenticated
            // content means the source served us two different messages under
            // one identity — that is the conflict worth rejecting.
            //
            // A shared `publish_time_ms` with a STRICTLY NEWER sequence is not a
            // conflict: Pyth's publish_time is second-granular while Pythnet
            // aggregates sub-second, so consecutive genuine aggregates routinely
            // share a publish second while carrying a new sequence and a moved
            // price. Rejecting those made a normal Pyth cadence look like an
            // attack and failed the whole refresh. Note the insert predicate
            // below already skips only on BOTH fields matching — the two
            // predicates disagreed, and this one was the wrong half.
            if entry.publish_time_ms == previous.publish_time_ms
                && entry.vaa_sequence == previous.vaa_sequence
            {
                let exact = entry.twap == previous.twap
                    && entry.confidence == previous.confidence
                    && entry.exponent == previous.exponent
                    && entry.trust_profile == previous.trust_profile;
                if !exact {
                    return Err(OracleCacheError::ConflictingReplay {
                        feed_id: feed_id.clone(),
                    });
                }
                replayed += 1;
            }
        }

        let accepted = entries.len().saturating_sub(replayed);
        for (feed_id, mut entry) in entries.drain(..) {
            if guard.get(&feed_id).is_some_and(|previous| {
                entry.publish_time_ms == previous.publish_time_ms
                    && entry.vaa_sequence == previous.vaa_sequence
            }) {
                continue;
            }
            entry.last_updated_ms = observed_at_ms;
            guard.insert(feed_id, entry);
        }
        Ok(BatchApplyReport { accepted, replayed })
    }

    /// Test/debug-only insertion boundary. It stamps both publish and arrival
    /// time to now and is used only by the feature-gated oracle seed endpoint.
    pub async fn seed_unverified(&self, feed_id: FeedId, mut price: CachedPrice) {
        let now = now_ms();
        price.publish_time_ms = now;
        price.last_updated_ms = now;
        let mut guard = self.inner.write().await;
        guard.insert(feed_id, price);
    }

    /// Read the current entry. Returns `None` if the feed has
    /// never been written. **Does not** check staleness — the
    /// caller (matching tick) owns the staleness policy.
    pub async fn get(&self, feed_id: &str) -> Option<CachedPrice> {
        self.inner.read().await.get(feed_id).cloned()
    }

    /// Return a market-scaled snapshot only when both signed publish time and
    /// local arrival health are fresh.
    pub async fn snapshot(
        &self,
        feed_id: &str,
        policy: FreshnessPolicy,
        units: OracleUnits,
    ) -> Result<OracleSnapshot, OracleCacheError> {
        self.snapshot_at(feed_id, policy, units, now_ms()).await
    }

    pub async fn snapshot_at(
        &self,
        feed_id: &str,
        policy: FreshnessPolicy,
        units: OracleUnits,
        observed_at_ms: u64,
    ) -> Result<OracleSnapshot, OracleCacheError> {
        let entry = self
            .get(feed_id)
            .await
            .ok_or_else(|| OracleCacheError::Missing(feed_id.to_string()))?;
        validate_signed_freshness(feed_id, &entry, policy, observed_at_ms)?;
        let local_age = observed_at_ms.saturating_sub(entry.last_updated_ms);
        if local_age > policy.max_age_ms {
            return Err(OracleCacheError::LocalStale {
                feed_id: feed_id.to_string(),
                age_ms: local_age,
                max_age_ms: policy.max_age_ms,
            });
        }
        Ok(OracleSnapshot {
            twap: convert_pyth_to_market_units(entry.twap, entry.exponent, units, true)?,
            confidence: convert_pyth_to_market_units(
                entry.confidence,
                entry.exponent,
                units,
                false,
            )?,
            publish_time_ms: entry.publish_time_ms,
            observed_at_ms,
            max_age_ms: policy.max_age_ms,
            max_future_skew_ms: policy.max_future_skew_ms,
        })
    }

    /// Used by integration tests + the `/transparency` endpoint.
    pub async fn feed_count(&self) -> usize {
        self.inner.read().await.len()
    }
}

fn validate_signed_freshness(
    feed_id: &str,
    entry: &CachedPrice,
    policy: FreshnessPolicy,
    now: u64,
) -> Result<(), OracleCacheError> {
    if entry.publish_time_ms > now.saturating_add(policy.max_future_skew_ms) {
        return Err(OracleCacheError::FutureDated {
            feed_id: feed_id.to_string(),
            publish_time_ms: entry.publish_time_ms,
            now_ms: now,
            max_future_skew_ms: policy.max_future_skew_ms,
        });
    }
    if now.saturating_sub(entry.publish_time_ms) > policy.max_age_ms {
        return Err(OracleCacheError::SignedStale {
            feed_id: feed_id.to_string(),
            publish_time_ms: entry.publish_time_ms,
            now_ms: now,
            max_age_ms: policy.max_age_ms,
        });
    }
    Ok(())
}

/// Convert a Pyth mantissa into the exact integer units used by market orders:
///
/// `floor(value × price_scale × 10^(exponent + quote_decimals - base_decimals))`
///
/// No floating point is used. The floor for a negative decimal exponent is
/// deliberate and matches settlement's floor pricing. A positive price that
/// would floor to zero is rejected as unrepresentable.
pub fn convert_pyth_to_market_units(
    value: u64,
    exponent: i32,
    units: OracleUnits,
    require_positive: bool,
) -> Result<u64, UnitConversionError> {
    if units.price_scale == 0 {
        return Err(UnitConversionError::ZeroPriceScale);
    }
    if value == 0 {
        return if require_positive {
            Err(UnitConversionError::Underflow)
        } else {
            Ok(0)
        };
    }

    let decimal_exponent = exponent
        .checked_add(i32::from(units.quote_decimals))
        .and_then(|value| value.checked_sub(i32::from(units.base_decimals)))
        .ok_or(UnitConversionError::ExponentOutOfRange {
            decimal_exponent: exponent,
        })?;
    let magnitude = decimal_exponent.unsigned_abs();
    let power = 10u128
        .checked_pow(magnitude)
        .ok_or(UnitConversionError::ExponentOutOfRange { decimal_exponent })?;
    let scaled = u128::from(value)
        .checked_mul(u128::from(units.price_scale))
        .ok_or(UnitConversionError::IntermediateOverflow)?;
    let result = if decimal_exponent >= 0 {
        scaled
            .checked_mul(power)
            .ok_or(UnitConversionError::IntermediateOverflow)?
    } else {
        scaled / power
    };
    if require_positive && result == 0 {
        return Err(UnitConversionError::Underflow);
    }
    u64::try_from(result).map_err(|_| UnitConversionError::OutputOverflow(result))
}

/// Milliseconds since UNIX epoch. Wraps the system clock; the
/// matcher uses this only for the cache staleness check, not for
/// anything cryptographic.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FEED: &str = "aa";

    fn policy() -> FreshnessPolicy {
        FreshnessPolicy {
            max_age_ms: 5_000,
            max_future_skew_ms: 1_000,
        }
    }

    fn entry(publish_time_ms: u64, sequence: u64) -> CachedPrice {
        CachedPrice {
            twap: 15_000_000_000,
            confidence: 100_000,
            exponent: -8,
            publish_time_ms,
            vaa_sequence: sequence,
            trust_profile: TrustProfile::RouterQuorumV1,
            last_updated_ms: 0,
            vaa: vec![1, 2, 3],
        }
    }

    #[test]
    fn converts_equal_decimal_market_exactly() {
        let units = OracleUnits {
            base_decimals: 6,
            quote_decimals: 6,
            price_scale: 100_000_000,
        };
        assert_eq!(
            convert_pyth_to_market_units(15_000_000_000, -8, units, true).unwrap(),
            15_000_000_000
        );
    }

    #[test]
    fn converts_sol_usdc_atomic_units() {
        let units = OracleUnits {
            base_decimals: 9,
            quote_decimals: 6,
            price_scale: 100_000_000_000,
        };
        // $150.00 becomes 0.15 atomic USDC lamports per SOL lamport; at a
        // 1e11 market scale that is 15e9.
        assert_eq!(
            convert_pyth_to_market_units(15_000_000_000, -8, units, true).unwrap(),
            15_000_000_000
        );

        let smaller_scale = OracleUnits {
            price_scale: 100_000_000,
            ..units
        };
        assert_eq!(
            convert_pyth_to_market_units(15_000_000_000, -8, smaller_scale, true).unwrap(),
            15_000_000
        );
    }

    #[test]
    fn conversion_floor_overflow_and_underflow_are_explicit() {
        let floor = OracleUnits {
            base_decimals: 1,
            quote_decimals: 0,
            price_scale: 1,
        };
        assert_eq!(convert_pyth_to_market_units(19, 0, floor, true).unwrap(), 1);
        assert_eq!(
            convert_pyth_to_market_units(1, 0, floor, true),
            Err(UnitConversionError::Underflow)
        );

        let overflow = OracleUnits {
            base_decimals: 0,
            quote_decimals: 38,
            price_scale: u64::MAX,
        };
        assert!(matches!(
            convert_pyth_to_market_units(u64::MAX, 0, overflow, true),
            Err(UnitConversionError::IntermediateOverflow)
        ));

        assert!(matches!(
            convert_pyth_to_market_units(
                1,
                i32::MAX,
                OracleUnits {
                    base_decimals: 0,
                    quote_decimals: 1,
                    price_scale: 1,
                },
                true,
            ),
            Err(UnitConversionError::ExponentOutOfRange { .. })
        ));
    }

    #[tokio::test]
    async fn signed_stale_future_and_non_monotonic_updates_fail_closed() {
        let cache = OracleCache::new();
        assert!(matches!(
            cache
                .apply_verified_batch_at(vec![(FEED.into(), entry(90_000, 1))], policy(), 100_000)
                .await,
            Err(OracleCacheError::SignedStale { .. })
        ));
        assert!(matches!(
            cache
                .apply_verified_batch_at(vec![(FEED.into(), entry(102_000, 1))], policy(), 100_000)
                .await,
            Err(OracleCacheError::FutureDated { .. })
        ));

        cache
            .apply_verified_batch_at(vec![(FEED.into(), entry(100_000, 10))], policy(), 100_000)
            .await
            .unwrap();
        assert!(matches!(
            cache
                .apply_verified_batch_at(vec![(FEED.into(), entry(99_999, 9))], policy(), 100_000)
                .await,
            Err(OracleCacheError::NonMonotonic { .. })
        ));
    }

    #[tokio::test]
    async fn exact_replay_does_not_refresh_local_arrival() {
        // The timings are chosen so the assertion can ONLY pass if local arrival
        // was left alone. Publish at 101_000 (within the 1_000 ms future-skew
        // allowance) but first observe at 100_000, then exact-replay at 103_000.
        // Reading at 105_500: signed age is 4_500 (fresh, under the 5_000 cap)
        // while local age is 5_500 (stale). If the replay had refreshed local
        // arrival to 103_000 the local age would be 2_500 and the snapshot would
        // succeed, failing this test.
        //
        // The previous version read at 105_001 with publish == first-arrival, so
        // BOTH clocks were stale and the assertion accepted either error. It
        // passed whether or not local arrival was refreshed — it could not fail
        // for the reason it exists.
        let cache = OracleCache::new();
        cache
            .apply_verified_batch_at(vec![(FEED.into(), entry(101_000, 10))], policy(), 100_000)
            .await
            .unwrap();
        let report = cache
            .apply_verified_batch_at(vec![(FEED.into(), entry(101_000, 10))], policy(), 103_000)
            .await
            .unwrap();
        assert_eq!(report.replayed, 1);

        let units = OracleUnits {
            base_decimals: 6,
            quote_decimals: 6,
            price_scale: 100_000_000,
        };
        assert!(
            matches!(
                cache.snapshot_at(FEED, policy(), units, 105_500).await,
                Err(OracleCacheError::LocalStale { .. })
            ),
            "expected LocalStale — signed freshness is still valid here, so \
             anything else means the exact replay refreshed local arrival"
        );
    }

    #[tokio::test]
    async fn same_publish_second_with_a_newer_sequence_is_accepted() {
        // Pyth's publish_time is second-granular while Pythnet aggregates
        // sub-second, so consecutive genuine updates routinely share a publish
        // second while carrying a new sequence and a moved price. That is normal
        // cadence, not a conflicting replay.
        let cache = OracleCache::new();
        cache
            .apply_verified_batch_at(vec![(FEED.into(), entry(100_000, 10))], policy(), 100_000)
            .await
            .unwrap();

        let mut moved = entry(100_000, 11);
        moved.twap = 15_500_000_000;
        let report = cache
            .apply_verified_batch_at(vec![(FEED.into(), moved)], policy(), 100_400)
            .await
            .expect("same publish second with a newer sequence must be accepted");
        assert_eq!(report.accepted, 1);
        assert_eq!(report.replayed, 0);

        let stored = cache.get(FEED).await.expect("entry present");
        assert_eq!(stored.twap, 15_500_000_000, "the newer price must win");
        assert_eq!(stored.vaa_sequence, 11);

        // The genuine conflict — same publish_time AND same sequence, different
        // authenticated content — is still rejected.
        let mut forged = entry(100_000, 11);
        forged.twap = 99_000_000_000;
        assert!(matches!(
            cache
                .apply_verified_batch_at(vec![(FEED.into(), forged)], policy(), 100_500)
                .await,
            Err(OracleCacheError::ConflictingReplay { .. })
        ));
    }

    #[tokio::test]
    async fn rejected_multi_feed_batch_is_atomic() {
        let cache = OracleCache::new();
        cache
            .apply_verified_batch_at(
                vec![
                    ("aa".into(), entry(100_000, 10)),
                    ("bb".into(), entry(100_000, 10)),
                ],
                policy(),
                100_000,
            )
            .await
            .unwrap();

        let mut changed = entry(101_000, 11);
        changed.twap = 16_000_000_000;
        let error = cache
            .apply_verified_batch_at(
                vec![("aa".into(), changed), ("bb".into(), entry(99_000, 9))],
                policy(),
                101_000,
            )
            .await
            .expect_err("one backwards feed must reject the whole batch");
        assert!(matches!(error, OracleCacheError::NonMonotonic { .. }));
        assert_eq!(cache.get("aa").await.unwrap().twap, 15_000_000_000);
        assert_eq!(cache.get("aa").await.unwrap().vaa_sequence, 10);
    }

    #[tokio::test]
    async fn snapshot_converts_and_preserves_signed_time() {
        let cache = OracleCache::new();
        cache
            .apply_verified_batch_at(vec![(FEED.into(), entry(100_000, 10))], policy(), 100_100)
            .await
            .unwrap();
        let snapshot = cache
            .snapshot_at(
                FEED,
                policy(),
                OracleUnits {
                    base_decimals: 9,
                    quote_decimals: 6,
                    price_scale: 100_000_000,
                },
                100_200,
            )
            .await
            .unwrap();
        assert_eq!(snapshot.twap, 15_000_000);
        assert_eq!(snapshot.publish_time_ms, 100_000);
        assert_eq!(snapshot.observed_at_ms, 100_200);
    }
}
