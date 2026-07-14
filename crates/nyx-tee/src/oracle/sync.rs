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
    accumulator,
    cache::{CachedPrice, OracleCache},
    hermes::HermesClient,
    vaa,
};

#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// Feed ids to refresh on every tick. One entry per market.
    /// Currently hardcoded at startup; later PRs will read this
    /// from the governed on-chain `MarketConfig` per mint pair.
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

    // The 32-byte feed id this update must contain a price message for.
    let feed_id_bytes: [u8; 32] = hex::decode(feed_id)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| anyhow::anyhow!("feed id {feed_id} is not 32 hex bytes"))?;

    // 1. Parse the raw AccumulatorUpdateData (PNAU) envelope → VAA + updates.
    let parsed = accumulator::parse(&update.accumulator)
        .map_err(|e| anyhow::anyhow!("accumulator parse failed: {e}"))?;

    // 2. Verify the Wormhole guardian signatures over the VAA. This is the
    //    cryptographic anchor: if it fails the VAA could be forged and we MUST
    //    NOT trust anything derived from it (including the Merkle root below).
    let vaa = vaa::verify(parsed.vaa)?;

    // 3. Extract the Merkle root from the *guardian-verified* VAA payload. This
    //    root — and ONLY this root — is bound by the guardian signatures.
    let root = accumulator::merkle_root_from_vaa_payload(vaa.payload)
        .map_err(|e| anyhow::anyhow!("wormhole merkle root parse failed: {e}"))?;

    // 4. Find the price message for our feed, prove its Merkle inclusion under
    //    the attested root, and decode it. The price we cache comes from THIS
    //    binary message — never from Hermes's JSON (C-05 / A-2). A message that
    //    fails inclusion means Hermes served a price not committed by the
    //    guardians: reject the whole refresh.
    let mut found: Option<accumulator::PriceFeedMessage> = None;
    for pu in &parsed.updates {
        let msg = match accumulator::parse_price_feed_message(pu.message) {
            Ok(m) => m,
            // Non-PriceFeedMessage discriminants (e.g. TWAP) — skip, not our
            // concern for this feed.
            Err(accumulator::AccumulatorError::NotPriceFeedMessage { .. }) => continue,
            Err(e) => return Err(anyhow::anyhow!("price message decode failed: {e}")),
        };
        if msg.feed_id != feed_id_bytes {
            continue;
        }
        if !accumulator::verify_inclusion(pu.message, &pu.proof, &root) {
            return Err(anyhow::anyhow!(
                accumulator::AccumulatorError::InclusionFailed {
                    feed_id: feed_id.to_string(),
                    recomputed: accumulator::compute_root(pu.message, &pu.proof),
                    attested: root,
                }
            ));
        }
        found = Some(msg);
        break;
    }
    let msg = found.ok_or_else(|| {
        anyhow::anyhow!(accumulator::AccumulatorError::FeedNotFound {
            feed_id: feed_id.to_string(),
        })
    })?;

    // 5. Reject a non-positive EMA price (matches the on-chain
    //    `OracleNegativePrice` guard) — done on the BINARY-proven value.
    if msg.ema_price <= 0 {
        return Err(anyhow::anyhow!(
            "binary-proven EMA price is non-positive ({}) — refusing to cache",
            msg.ema_price
        ));
    }
    let ema_price = msg.ema_price as u64;

    // 6. Cross-check the binary-proven value against Hermes's JSON. They MUST
    //    agree; a split means Hermes lied in one of them (or we have a decode
    //    bug). Reject loudly rather than silently trusting either.
    if ema_price != update.json_ema_price || msg.exponent != update.json_exponent {
        return Err(anyhow::anyhow!(
            "Hermes JSON/binary price mismatch for {feed_id}: binary ema={ema_price} expo={} \
             vs json ema={} expo={} — refusing to cache",
            msg.exponent,
            update.json_ema_price,
            update.json_exponent,
        ));
    }

    // Pyth publish_time is seconds; the cache stores ms. Guard against a
    // negative timestamp before the cast.
    let publish_time_ms = (msg.publish_time.max(0) as u64).saturating_mul(1000);

    let entry = CachedPrice {
        twap: ema_price,
        confidence: msg.ema_conf,
        exponent: msg.exponent,
        publish_time_ms,
        // `last_updated_ms` gets stamped inside upsert().
        last_updated_ms: 0,
        vaa: parsed.vaa.to_vec(),
    };
    cache.upsert(feed_id.to_string(), entry).await;

    tracing::debug!(
        feed_id,
        ema_price,
        publish_time_ms,
        merkle_verified = true,
        "oracle sync: refreshed feed (Merkle-verified)"
    );
    Ok(())
}
