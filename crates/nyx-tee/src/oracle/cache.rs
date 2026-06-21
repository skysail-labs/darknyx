//! Concurrent oracle-price cache. The `sync` task writes; the
//! matcher tick reads. `tokio::sync::RwLock` so readers don't
//! block each other and the write window is microseconds.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::RwLock;

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
    /// Pyth exponent (negative power of 10). Informational at the
    /// matcher layer.
    pub exponent: i32,
    /// Pyth-reported publish time, milliseconds since UNIX epoch.
    pub publish_time_ms: u64,
    /// When the sync task last wrote this entry, monotonic clock
    /// ms since process start. Used to compute the matcher's
    /// staleness check independently of Pyth's `publish_time_ms`
    /// (which can drift if our system clock is wrong).
    pub last_updated_ms: u64,
    /// Raw VAA bytes that backed this update. Kept for the
    /// future v3 path where the on-chain `verify_match_batch`
    /// re-verifies Pyth signatures directly.
    pub vaa: Vec<u8>,
}

/// `OracleSnapshot` is what the matcher tick consumes — same shape
/// the `darkpool_matcher::OracleSnapshot` type expects. We mirror
/// the field set here for clarity; the conversion is one
/// `From<CachedPrice> for matcher::OracleSnapshot` impl that lives
/// alongside the matcher integration (PR 4c).
#[derive(Debug, Clone)]
pub struct OracleSnapshot {
    pub twap: u64,
    pub confidence: u64,
    pub exponent: i32,
    /// Solana slot at which we last refreshed this price. Drives
    /// the matcher's `MAX_STALE` check.
    pub publish_slot: u64,
}

#[derive(Clone, Default)]
pub struct OracleCache {
    inner: Arc<RwLock<HashMap<FeedId, CachedPrice>>>,
}

impl OracleCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace (or insert) the entry for `feed_id`. Stamps
    /// `last_updated_ms` to `now_ms()`.
    pub async fn upsert(&self, feed_id: FeedId, mut price: CachedPrice) {
        price.last_updated_ms = now_ms();
        let mut guard = self.inner.write().await;
        guard.insert(feed_id, price);
    }

    /// Read the current entry. Returns `None` if the feed has
    /// never been written. **Does not** check staleness — the
    /// caller (matching tick) owns the staleness policy.
    pub async fn get(&self, feed_id: &str) -> Option<CachedPrice> {
        self.inner.read().await.get(feed_id).cloned()
    }

    /// Convenience: return a snapshot in the matcher's shape, or
    /// `None` if the cache entry is missing OR older than
    /// `max_age_ms`.
    pub async fn snapshot(
        &self,
        feed_id: &str,
        max_age_ms: u64,
        slot_now: u64,
    ) -> Option<OracleSnapshot> {
        let entry = self.get(feed_id).await?;
        if now_ms().saturating_sub(entry.last_updated_ms) > max_age_ms {
            tracing::warn!(
                feed_id,
                age_ms = now_ms().saturating_sub(entry.last_updated_ms),
                max_age_ms,
                "oracle cache entry stale; refusing to serve snapshot"
            );
            return None;
        }
        Some(OracleSnapshot {
            twap: entry.twap,
            confidence: entry.confidence,
            exponent: entry.exponent,
            publish_slot: slot_now,
        })
    }

    /// Used by integration tests + the `/transparency` endpoint.
    pub async fn feed_count(&self) -> usize {
        self.inner.read().await.len()
    }
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
