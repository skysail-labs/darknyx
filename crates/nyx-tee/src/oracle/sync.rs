//! Background tokio task that refreshes the `OracleCache`.
//!
//! At a fixed interval (default 1 s) the task iterates the
//! configured feed ids, calls Hermes, verifies the VAA, and
//! writes the result into the cache. Errors are logged but
//! don't kill the task — Hermes is occasionally flaky and we
//! want the cache to recover on the next tick.
//!
//! Lifecycle: spawned at boot (after `keys::derive` runs).
//! Returns a `JoinHandle<()>` the caller can `.abort()` on
//! shutdown.

use std::time::Duration;
use tokio::task::JoinHandle;
use tokio::time;

use crate::oracle::{
    cache::{CachedPrice, OracleCache},
    hermes::HermesClient,
    vaa,
};

#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// Feed ids to refresh on every tick. One entry per market.
    /// Currently hardcoded at startup; later PRs will read this
    /// from on-chain `MatchingConfig` per market.
    pub feed_ids: Vec<String>,
    /// Refresh cadence. Default 1 s — fast enough that the
    /// matcher's 2 s tick always sees a fresh value, slow enough
    /// that we don't hammer Hermes.
    pub interval: Duration,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            feed_ids: Vec::new(),
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
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = time::interval(cfg.interval);
        // Make the first tick fire immediately so the cache is
        // warm before the matching loop starts.
        ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            for feed_id in &cfg.feed_ids {
                if let Err(e) = refresh_one(&client, &cache, feed_id).await {
                    // Don't abort the task on a single feed's
                    // failure — log and try again next tick. The
                    // matcher's staleness check will refuse to
                    // serve a stale snapshot, so a Hermes outage
                    // becomes "matching tick noops" not "TEE
                    // serves stale prices".
                    tracing::warn!(
                        feed_id,
                        error = %e,
                        "oracle sync: feed refresh failed"
                    );
                }
            }
        }
    })
}

/// One refresh cycle for a single feed. Returns `Err` on any
/// failure (network, JSON, VAA verification) so the caller can
/// log + move on.
async fn refresh_one(
    client: &HermesClient,
    cache: &OracleCache,
    feed_id: &str,
) -> anyhow::Result<()> {
    let update = client.fetch(feed_id).await?;

    // Verify the Wormhole guardian signatures over the VAA. This
    // is the cryptographic anchor: if it fails, the VAA could be
    // forged and we MUST NOT cache the price.
    let _vaa = vaa::verify(&update.vaa)?;

    let entry = CachedPrice {
        twap: update.ema_price,
        confidence: update.confidence,
        exponent: update.exponent,
        publish_time_ms: update.publish_time_ms,
        // `last_updated_ms` gets stamped inside upsert().
        last_updated_ms: 0,
        vaa: update.vaa,
    };
    cache.upsert(feed_id.to_string(), entry).await;

    tracing::debug!(
        feed_id,
        ema_price = update.ema_price,
        publish_time_ms = update.publish_time_ms,
        "oracle sync: refreshed feed"
    );
    Ok(())
}
