//! Finalized Solana reader for upgraded Pyth Core sponsored push feeds.
//!
//! The Pyth receiver has already verified the router quorum and Merkle proof
//! before writing `PriceUpdateV2`.  This adapter independently pins the
//! upgraded receiver/push program ids, derives shard-0 feed PDAs, requires full
//! verification, and validates owner/write-authority/feed/timestamps before an
//! entry reaches the shared cache.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use borsh::BorshDeserialize;
use solana_address::Address;
use tokio::task::JoinHandle;
use tokio::time;

use crate::matcher::TradingPauseReason;
use crate::oracle::cache::{
    convert_pyth_to_market_units, now_ms, CachedPrice, FreshnessPolicy, OracleCache, OracleUnits,
};
use crate::oracle::source::OracleSourceKind;
use crate::oracle::sync::{reconcile_market_health, MarketOracleBinding};
use crate::solana_rpc::{RpcAccountInfo, SolanaRpcClient};

/// Upgraded, Pro-compatible Pyth Core receiver and sponsored push-oracle ids.
/// Pyth publishes the same ids on Solana mainnet and devnet.
pub const PYTH_CORE_RECEIVER_PROGRAM_ID: &str = "rec2HHDDnjLfj4kE7VyEtFA1HPGQLK33259532cRyHp";
pub const PYTH_CORE_PUSH_ORACLE_PROGRAM_ID: &str = "pyt2F414BA6dPttK6RddPZUdHfapoBN24GL5wbrPCou";
pub const PYTH_PUSH_SHARD_ID: u16 = 0;

const PRICE_UPDATE_V2_DISCRIMINATOR: [u8; 8] = [0x22, 0xf1, 0x23, 0x63, 0x9d, 0x7e, 0xf4, 0xcd];

#[derive(Debug, Clone)]
pub struct PushSyncConfig {
    pub feed_ids: Vec<String>,
    pub market_bindings: Vec<MarketOracleBinding>,
    pub freshness: FreshnessPolicy,
    pub interval: Duration,
}

#[derive(Debug, Clone)]
struct PushFeedTarget {
    normalized_feed_id: String,
    feed_id: [u8; 32],
    address: Address,
}

#[derive(Debug, BorshDeserialize)]
enum VerificationLevel {
    Partial { num_signatures: u8 },
    Full,
}

#[derive(Debug, BorshDeserialize)]
struct PriceFeedMessage {
    feed_id: [u8; 32],
    price: i64,
    conf: u64,
    exponent: i32,
    publish_time: i64,
    prev_publish_time: i64,
    ema_price: i64,
    ema_conf: u64,
}

#[derive(Debug, BorshDeserialize)]
struct PriceUpdateV2 {
    write_authority: [u8; 32],
    verification_level: VerificationLevel,
    price_message: PriceFeedMessage,
    posted_slot: u64,
}

pub fn derive_push_feed_address(feed_id: &[u8; 32]) -> anyhow::Result<Address> {
    let program: Address = PYTH_CORE_PUSH_ORACLE_PROGRAM_ID
        .parse()
        .map_err(|error| anyhow::anyhow!("invalid pinned Pyth push program id: {error}"))?;
    Ok(Address::find_program_address(&[&PYTH_PUSH_SHARD_ID.to_le_bytes(), feed_id], &program).0)
}

fn prepare_targets(feed_ids: &[String]) -> anyhow::Result<Vec<PushFeedTarget>> {
    feed_ids
        .iter()
        .map(|feed_id| {
            let normalized = feed_id.trim_start_matches("0x").to_ascii_lowercase();
            let bytes: [u8; 32] = hex::decode(&normalized)
                .ok()
                .and_then(|value| value.try_into().ok())
                .ok_or_else(|| anyhow::anyhow!("feed id {feed_id} is not 32 hex bytes"))?;
            Ok(PushFeedTarget {
                normalized_feed_id: normalized,
                feed_id: bytes,
                address: derive_push_feed_address(&bytes)?,
            })
        })
        .collect()
}

fn decode_price_account(
    target: &PushFeedTarget,
    account: &RpcAccountInfo,
    context_slot: u64,
) -> anyhow::Result<CachedPrice> {
    let expected_owner: Address = PYTH_CORE_RECEIVER_PROGRAM_ID
        .parse()
        .map_err(|error| anyhow::anyhow!("invalid pinned Pyth receiver program id: {error}"))?;
    anyhow::ensure!(
        account.owner == expected_owner,
        "Pyth push account {} has owner {}, expected {}",
        target.address,
        account.owner,
        expected_owner
    );
    anyhow::ensure!(!account.executable, "Pyth price account is executable");
    anyhow::ensure!(
        account.data.starts_with(&PRICE_UPDATE_V2_DISCRIMINATOR),
        "Pyth push account has the wrong PriceUpdateV2 discriminator"
    );
    let mut payload = &account.data[PRICE_UPDATE_V2_DISCRIMINATOR.len()..];
    let update = PriceUpdateV2::deserialize(&mut payload)
        .map_err(|error| anyhow::anyhow!("decode Pyth PriceUpdateV2: {error}"))?;
    // The account is allocated for the largest VerificationLevel enum variant.
    // `Full` serializes one byte shorter than `Partial`, leaving zero padding.
    anyhow::ensure!(
        payload.iter().all(|byte| *byte == 0),
        "Pyth PriceUpdateV2 has non-zero trailing bytes"
    );
    anyhow::ensure!(
        update.write_authority == target.address.to_bytes(),
        "Pyth push account write authority is not its derived push PDA"
    );
    match update.verification_level {
        VerificationLevel::Full => {}
        VerificationLevel::Partial { num_signatures } => anyhow::bail!(
            "Pyth push account is only partially verified ({num_signatures} signatures)"
        ),
    }
    anyhow::ensure!(
        update.price_message.feed_id == target.feed_id,
        "Pyth push account feed id does not match its derived address"
    );
    anyhow::ensure!(
        update.price_message.ema_price > 0,
        "Pyth push EMA price is non-positive"
    );
    anyhow::ensure!(
        update.price_message.publish_time >= 0,
        "Pyth push publish time is negative"
    );
    anyhow::ensure!(update.posted_slot > 0, "Pyth push posted slot is zero");
    anyhow::ensure!(
        update.posted_slot <= context_slot,
        "Pyth push posted slot {} exceeds finalized RPC context slot {context_slot}",
        update.posted_slot
    );
    // Decode and sanity-check the spot fields even though matching deliberately
    // uses Pyth's EMA as its circuit-breaker anchor.
    anyhow::ensure!(
        update.price_message.price > 0,
        "Pyth spot price is non-positive"
    );
    let _ = (
        update.price_message.conf,
        update.price_message.prev_publish_time,
    );
    let publish_time_ms = (update.price_message.publish_time as u64)
        .checked_mul(1_000)
        .ok_or_else(|| anyhow::anyhow!("Pyth push publish time overflow"))?;
    Ok(CachedPrice {
        twap: update.price_message.ema_price as u64,
        confidence: update.price_message.ema_conf,
        exponent: update.price_message.exponent,
        publish_time_ms,
        source_sequence: update.posted_slot,
        source: OracleSourceKind::PythSolanaPushV1,
        last_updated_ms: 0,
        evidence: Vec::new(),
    })
}

fn validate_market_units(
    cfg: &PushSyncConfig,
    feed_id: &str,
    price: &CachedPrice,
) -> anyhow::Result<()> {
    let targets = cfg
        .market_bindings
        .iter()
        .filter(|binding| binding.feed_id.eq_ignore_ascii_case(feed_id))
        .map(|binding| binding.units)
        .collect::<HashSet<OracleUnits>>();
    anyhow::ensure!(
        !targets.is_empty(),
        "no governed unit binding for feed {feed_id}"
    );
    for units in targets {
        convert_pyth_to_market_units(price.twap, price.exponent, units, true)?;
        convert_pyth_to_market_units(price.confidence, price.exponent, units, false)?;
    }
    Ok(())
}

fn config_for_feed(cfg: &PushSyncConfig, feed_id: &str) -> PushSyncConfig {
    PushSyncConfig {
        feed_ids: vec![feed_id.to_string()],
        market_bindings: cfg
            .market_bindings
            .iter()
            .filter(|binding| binding.feed_id.eq_ignore_ascii_case(feed_id))
            .cloned()
            .collect(),
        freshness: cfg.freshness,
        interval: cfg.interval,
    }
}

/// Spawn the non-blocking finalized-account producer. A failed poll never
/// deletes or overwrites the last verified cache value; market health is
/// reconciled from signed age, so transient RPC errors do not interrupt a
/// matching/proving/settlement cycle already in progress.
pub fn spawn_push_oracle_sync(
    cache: OracleCache,
    rpc: SolanaRpcClient,
    cfg: PushSyncConfig,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let targets = match prepare_targets(&cfg.feed_ids) {
            Ok(targets) if !targets.is_empty() => targets,
            Ok(_) => {
                tracing::error!("Pyth push sync has no configured feeds");
                return;
            }
            Err(error) => {
                for binding in &cfg.market_bindings {
                    binding.trading_gate.pause_for(TradingPauseReason::Oracle);
                }
                tracing::error!(error = %error, "Pyth push sync configuration invalid; markets PAUSED");
                return;
            }
        };
        let addresses = targets
            .iter()
            .map(|target| target.address)
            .collect::<Vec<_>>();
        let mut ticker = time::interval(cfg.interval);
        ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let started = Instant::now();
            let response = match rpc.get_multiple_accounts_with_context(&addresses).await {
                Ok(response) => response,
                Err(error) => {
                    reconcile_market_health(
                        &cache,
                        &cfg.market_bindings,
                        cfg.freshness,
                        OracleSourceKind::PythSolanaPushV1,
                    )
                    .await;
                    tracing::warn!(
                        source = OracleSourceKind::PythSolanaPushV1.as_str(),
                        error = %error,
                        refresh_ms = started.elapsed().as_millis() as u64,
                        "Pyth push poll failed; retaining last verified prices while fresh"
                    );
                    continue;
                }
            };

            let mut accepted = 0usize;
            let mut replayed = 0usize;
            for (target, account) in targets.iter().zip(response.accounts.iter()) {
                let feed_cfg = config_for_feed(&cfg, &target.normalized_feed_id);
                let result = async {
                    let account = account.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("derived Pyth push account {} is missing", target.address)
                    })?;
                    let price = decode_price_account(target, account, response.context_slot)?;
                    validate_market_units(&feed_cfg, &target.normalized_feed_id, &price)?;
                    let report = cache
                        .apply_verified_batch_at(
                            vec![(target.normalized_feed_id.clone(), price)],
                            cfg.freshness,
                            now_ms(),
                        )
                        .await?;
                    anyhow::Ok(report)
                }
                .await;
                match result {
                    Ok(report) => {
                        accepted += report.accepted;
                        replayed += report.replayed;
                    }
                    Err(error) => tracing::warn!(
                        source = OracleSourceKind::PythSolanaPushV1.as_str(),
                        feed_id = target.normalized_feed_id,
                        error = %error,
                        "Pyth push feed rejected; retaining last verified price while fresh"
                    ),
                }
                reconcile_market_health(
                    &cache,
                    &feed_cfg.market_bindings,
                    cfg.freshness,
                    OracleSourceKind::PythSolanaPushV1,
                )
                .await;
            }
            tracing::debug!(
                source = OracleSourceKind::PythSolanaPushV1.as_str(),
                feed_count = targets.len(),
                rpc_requests = 1,
                context_slot = response.context_slot,
                accepted,
                replayed,
                refresh_ms = started.elapsed().as_millis() as u64,
                "Pyth push oracle refresh complete"
            );
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use borsh::BorshSerialize;

    const SOL_FEED: &str = "ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d";

    #[derive(BorshSerialize)]
    enum TestVerificationLevel {
        Partial { num_signatures: u8 },
        Full,
    }

    #[derive(BorshSerialize)]
    struct TestPriceFeedMessage {
        feed_id: [u8; 32],
        price: i64,
        conf: u64,
        exponent: i32,
        publish_time: i64,
        prev_publish_time: i64,
        ema_price: i64,
        ema_conf: u64,
    }

    #[derive(BorshSerialize)]
    struct TestPriceUpdateV2 {
        write_authority: [u8; 32],
        verification_level: TestVerificationLevel,
        price_message: TestPriceFeedMessage,
        posted_slot: u64,
    }

    fn target() -> PushFeedTarget {
        prepare_targets(&[SOL_FEED.to_string()]).unwrap().remove(0)
    }

    fn account(
        target: &PushFeedTarget,
        verification_level: TestVerificationLevel,
    ) -> RpcAccountInfo {
        let mut data = PRICE_UPDATE_V2_DISCRIMINATOR.to_vec();
        data.extend(
            borsh::to_vec(&TestPriceUpdateV2 {
                write_authority: target.address.to_bytes(),
                verification_level,
                price_message: TestPriceFeedMessage {
                    feed_id: target.feed_id,
                    price: 15_000_000_000,
                    conf: 10,
                    exponent: -8,
                    publish_time: 1_800_000_000,
                    prev_publish_time: 1_799_999_999,
                    ema_price: 14_900_000_000,
                    ema_conf: 12,
                },
                posted_slot: 900,
            })
            .unwrap(),
        );
        RpcAccountInfo {
            lamports: 1,
            owner: PYTH_CORE_RECEIVER_PROGRAM_ID.parse().unwrap(),
            data,
            executable: false,
            rent_epoch: 0,
        }
    }

    #[test]
    fn derives_the_official_upgraded_sol_push_account() {
        assert_eq!(
            target().address.to_string(),
            "7AviUf9nL62mcxNbQGKm4nKDQnPjswo6c5MX4D57HmyE"
        );
    }

    #[test]
    fn accepts_only_full_correctly_owned_feed_accounts() {
        let target = target();
        let decoded = decode_price_account(
            &target,
            &account(&target, TestVerificationLevel::Full),
            1_000,
        )
        .unwrap();
        assert_eq!(decoded.twap, 14_900_000_000);
        assert_eq!(decoded.source_sequence, 900);
        assert_eq!(decoded.source, OracleSourceKind::PythSolanaPushV1);

        let partial = account(
            &target,
            TestVerificationLevel::Partial { num_signatures: 2 },
        );
        assert!(decode_price_account(&target, &partial, 1_000).is_err());

        let mut wrong_owner = account(&target, TestVerificationLevel::Full);
        wrong_owner.owner = Address::new_from_array([7; 32]);
        assert!(decode_price_account(&target, &wrong_owner, 1_000).is_err());
    }

    #[test]
    fn rejects_feed_substitution_and_future_posted_slots() {
        let target = target();
        let mut substituted = account(&target, TestVerificationLevel::Full);
        substituted.data[41] ^= 1;
        assert!(decode_price_account(&target, &substituted, 1_000).is_err());
        assert!(
            decode_price_account(&target, &account(&target, TestVerificationLevel::Full), 899)
                .is_err()
        );
    }
}
