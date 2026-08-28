//! Opt-in production-oracle validation against an offline loopback Surfnet.

use std::future::Future;
use std::time::{Duration, Instant};

use borsh::BorshSerialize;
use darknyx_tee::matcher::{TradingGate, TradingPauseReason};
use darknyx_tee::oracle::push::PYTH_CORE_RECEIVER_PROGRAM_ID;
use darknyx_tee::oracle::{
    derive_push_feed_address, spawn_push_oracle_sync, FreshnessPolicy, MarketOracleBinding,
    OracleCache, OracleUnits, PushSyncConfig,
};
use darknyx_tee::solana_rpc::SolanaRpcClient;
use reqwest::{Client, Url};
use serde_json::{json, Value};
use solana_address::Address;

const PRICE_UPDATE_V2_DISCRIMINATOR: [u8; 8] = [0x22, 0xf1, 0x23, 0x63, 0x9d, 0x7e, 0xf4, 0xcd];
const CLOCK_SYSVAR: &str = "SysvarC1ock11111111111111111111111111111111";

#[derive(Clone, Copy, Debug)]
enum Mutation {
    Valid,
    WrongPda,
    WrongOwner,
    WrongWriteAuthority,
    WrongFeed,
    PartialVerification,
    StaleTime,
    FutureTime,
    InvalidExponent,
    NonPositiveSpot,
    NonPositiveEma,
    FuturePostedSlot,
    WrongDiscriminator,
    NonZeroTrailing,
    Malformed,
}

impl Mutation {
    fn name(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::WrongPda => "wrong-pda",
            Self::WrongOwner => "wrong-owner",
            Self::WrongWriteAuthority => "wrong-write-authority",
            Self::WrongFeed => "wrong-feed",
            Self::PartialVerification => "partial-verification",
            Self::StaleTime => "stale-time",
            Self::FutureTime => "future-time",
            Self::InvalidExponent => "invalid-exponent",
            Self::NonPositiveSpot => "nonpositive-spot",
            Self::NonPositiveEma => "nonpositive-ema",
            Self::FuturePostedSlot => "future-posted-slot",
            Self::WrongDiscriminator => "wrong-discriminator",
            Self::NonZeroTrailing => "nonzero-trailing-data",
            Self::Malformed => "malformed",
        }
    }
}

#[derive(BorshSerialize)]
enum FixtureVerificationLevel {
    Partial { num_signatures: u8 },
    Full,
}

#[derive(BorshSerialize)]
struct FixturePriceFeedMessage {
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
struct FixturePriceUpdateV2 {
    write_authority: [u8; 32],
    verification_level: FixtureVerificationLevel,
    price_message: FixturePriceFeedMessage,
    posted_slot: u64,
}

struct EncodedAccount {
    address: Address,
    owner: Address,
    data: Vec<u8>,
}

fn require_loopback_rpc() -> Option<String> {
    if std::env::var("RUN_SURFPOOL_ORACLE_FIXTURE").ok().as_deref() != Some("1") {
        return None;
    }
    let rpc_url = std::env::var("SOLANA_RPC_URL").expect("SOLANA_RPC_URL");
    let parsed = Url::parse(&rpc_url).expect("valid SOLANA_RPC_URL");
    assert_eq!(parsed.scheme(), "http", "fixture RPC must use local HTTP");
    assert!(
        matches!(parsed.host_str(), Some("127.0.0.1" | "localhost" | "::1")),
        "fixture refuses a non-loopback RPC"
    );
    Some(rpc_url)
}

async fn raw_rpc(client: &Client, rpc_url: &str, method: &str, params: Value) -> Value {
    let response = client
        .post(rpc_url)
        .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
        .send()
        .await
        .unwrap_or_else(|error| panic!("{method} request: {error}"));
    assert!(response.status().is_success(), "{method} HTTP status");
    let body: Value = response.json().await.expect("JSON-RPC body");
    assert!(body.get("error").is_none(), "{method}: {body}");
    body.get("result").cloned().expect("JSON-RPC result")
}

async fn surfnet_clock(rpc: &SolanaRpcClient) -> (u64, i64) {
    let address: Address = CLOCK_SYSVAR.parse().expect("clock sysvar id");
    let account = rpc
        .get_account_info(&address)
        .await
        .expect("clock RPC")
        .expect("clock sysvar exists");
    assert!(account.data.len() >= 40, "clock sysvar layout");
    let slot = u64::from_le_bytes(account.data[0..8].try_into().unwrap());
    let unix_timestamp = i64::from_le_bytes(account.data[32..40].try_into().unwrap());
    assert!(slot > 0, "fixture requires a nonzero Surfnet slot");
    assert!(
        unix_timestamp > 0,
        "fixture requires a positive Surfnet time"
    );
    (slot, unix_timestamp)
}

fn encoded_account(
    mutation: Mutation,
    feed_id: [u8; 32],
    slot: u64,
    unix_timestamp: i64,
) -> EncodedAccount {
    let expected_address = derive_push_feed_address(&feed_id).expect("push PDA");
    let mut address = expected_address;
    let mut owner: Address = PYTH_CORE_RECEIVER_PROGRAM_ID
        .parse()
        .expect("receiver program id");
    let mut write_authority = expected_address.to_bytes();
    let mut embedded_feed = feed_id;
    let mut verification_level = FixtureVerificationLevel::Full;
    let mut price = 15_000_000_000i64;
    let mut ema_price = 14_900_000_000i64;
    let mut exponent = -8i32;
    let mut publish_time = unix_timestamp;
    let mut posted_slot = slot;

    match mutation {
        Mutation::Valid
        | Mutation::WrongDiscriminator
        | Mutation::NonZeroTrailing
        | Mutation::Malformed => {}
        Mutation::WrongPda => address = Address::new_from_array([0xa5; 32]),
        Mutation::WrongOwner => owner = Address::new_from_array([0x77; 32]),
        Mutation::WrongWriteAuthority => write_authority[0] ^= 1,
        Mutation::WrongFeed => embedded_feed[0] ^= 1,
        Mutation::PartialVerification => {
            verification_level = FixtureVerificationLevel::Partial { num_signatures: 2 }
        }
        Mutation::StaleTime => publish_time -= 120,
        Mutation::FutureTime => publish_time += 120,
        Mutation::InvalidExponent => exponent = 100,
        Mutation::NonPositiveSpot => price = 0,
        Mutation::NonPositiveEma => ema_price = 0,
        Mutation::FuturePostedSlot => posted_slot += 100,
    }

    let mut data = PRICE_UPDATE_V2_DISCRIMINATOR.to_vec();
    data.extend(
        borsh::to_vec(&FixturePriceUpdateV2 {
            write_authority,
            verification_level,
            price_message: FixturePriceFeedMessage {
                feed_id: embedded_feed,
                price,
                conf: 10,
                exponent,
                publish_time,
                prev_publish_time: publish_time - 1,
                ema_price,
                ema_conf: 12,
            },
            posted_slot,
        })
        .expect("serialize PriceUpdateV2"),
    );
    // Full is one byte shorter than the account allocation's largest enum
    // variant. The production decoder requires the unused allocation to be 0.
    if !matches!(mutation, Mutation::PartialVerification) {
        data.push(0);
    }
    match mutation {
        Mutation::WrongDiscriminator => data[0] ^= 1,
        Mutation::NonZeroTrailing => data.push(1),
        Mutation::Malformed => data.truncate(20),
        _ => {}
    }
    EncodedAccount {
        address,
        owner,
        data,
    }
}

async fn install_account(client: &Client, rpc_url: &str, account: &EncodedAccount) {
    raw_rpc(
        client,
        rpc_url,
        "surfnet_setAccount",
        json!([account.address.to_string(), {
            "lamports": 1_000_000,
            "data": hex::encode(&account.data),
            "owner": account.owner.to_string(),
            "executable": false,
            "rentEpoch": 0
        }]),
    )
    .await;
}

async fn wait_until<F, Fut>(timeout: Duration, mut predicate: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if predicate().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

async fn exercise_case(
    client: &Client,
    rpc_url: &str,
    mutation: Mutation,
    case_index: u8,
    slot: u64,
    unix_timestamp: i64,
) {
    let feed_id = [case_index; 32];
    let feed_hex = hex::encode(feed_id);
    let sentinel_feed_id = [case_index | 0x80; 32];
    let sentinel_feed_hex = hex::encode(sentinel_feed_id);
    let account = encoded_account(mutation, feed_id, slot, unix_timestamp);
    let sentinel_account = encoded_account(Mutation::Valid, sentinel_feed_id, slot, unix_timestamp);
    install_account(client, rpc_url, &account).await;
    install_account(client, rpc_url, &sentinel_account).await;

    let cache = OracleCache::new();
    let gate = TradingGate::default();
    let sentinel_gate = TradingGate::default();
    gate.pause_for(TradingPauseReason::Oracle);
    sentinel_gate.pause_for(TradingPauseReason::Oracle);
    let policy = FreshnessPolicy {
        max_age_ms: 30_000,
        max_future_skew_ms: 1_000,
    };
    let units = OracleUnits {
        base_decimals: 6,
        quote_decimals: 6,
        price_scale: 100_000_000,
    };
    let task = spawn_push_oracle_sync(
        cache.clone(),
        SolanaRpcClient::new(rpc_url).expect("Surfpool RPC client"),
        PushSyncConfig {
            feed_ids: vec![feed_hex.clone(), sentinel_feed_hex.clone()],
            market_bindings: vec![
                MarketOracleBinding {
                    symbol: format!("FIXTURE-{}", mutation.name()),
                    feed_id: feed_hex.clone(),
                    units,
                    trading_gate: gate.clone(),
                },
                MarketOracleBinding {
                    symbol: format!("SENTINEL-{}", mutation.name()),
                    feed_id: sentinel_feed_hex.clone(),
                    units,
                    trading_gate: sentinel_gate.clone(),
                },
            ],
            freshness: policy,
            interval: Duration::from_millis(20),
        },
    );

    // Both targets are fetched in one production getMultipleAccounts poll and
    // the target is processed first. Observing the valid sentinel therefore
    // proves the mutated target was evaluated; a fixed sleep cannot do that on
    // a loaded runner.
    assert!(
        wait_until(Duration::from_secs(2), || async {
            cache.get(&sentinel_feed_hex).await.is_some() && sentinel_gate.is_open()
        })
        .await,
        "sentinel fixture was not accepted"
    );

    if matches!(mutation, Mutation::Valid) {
        assert!(
            wait_until(Duration::from_secs(2), || async {
                cache.get(&feed_hex).await.is_some() && gate.is_open()
            })
            .await,
            "valid fixture was not accepted"
        );
    } else {
        assert!(
            cache.get(&feed_hex).await.is_none(),
            "{} fixture reached the production cache",
            mutation.name()
        );
        assert!(
            gate.is_paused_for(TradingPauseReason::Oracle),
            "{} fixture opened the market gate",
            mutation.name()
        );

        // Turn the same target into a valid account and require recovery. This
        // proves the negative assertion observed a live poller rather than a
        // task that never executed.
        let corrected = encoded_account(Mutation::Valid, feed_id, slot, unix_timestamp);
        install_account(client, rpc_url, &corrected).await;
        assert!(
            wait_until(Duration::from_secs(2), || async {
                cache.get(&feed_hex).await.is_some() && gate.is_open()
            })
            .await,
            "{} case did not recover after a valid replacement",
            mutation.name()
        );
    }

    let cached = cache.get(&feed_hex).await.expect("accepted fixture");
    assert_eq!(cached.twap, 14_900_000_000);
    assert_eq!(cached.source_sequence, slot);
    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn production_push_sync_accepts_only_exact_surfpool_fixtures() {
    let Some(rpc_url) = require_loopback_rpc() else {
        return;
    };
    let rpc = SolanaRpcClient::new(&rpc_url).expect("Surfpool RPC client");
    let client = Client::new();
    let cases = [
        Mutation::WrongPda,
        Mutation::WrongOwner,
        Mutation::WrongWriteAuthority,
        Mutation::WrongFeed,
        Mutation::PartialVerification,
        Mutation::StaleTime,
        Mutation::FutureTime,
        Mutation::InvalidExponent,
        Mutation::NonPositiveSpot,
        Mutation::NonPositiveEma,
        Mutation::FuturePostedSlot,
        Mutation::WrongDiscriminator,
        Mutation::NonZeroTrailing,
        Mutation::Malformed,
        Mutation::Valid,
    ];
    for (index, mutation) in cases.into_iter().enumerate() {
        let (slot, unix_timestamp) = surfnet_clock(&rpc).await;
        exercise_case(
            &client,
            &rpc_url,
            mutation,
            u8::try_from(index + 1).unwrap(),
            slot,
            unix_timestamp,
        )
        .await;
    }
    let (slot, unix_timestamp) = surfnet_clock(&rpc).await;
    eprintln!(
        "SURFPOOL_ORACLE_FIXTURE cases={} valid=1 rejected={} recovered={} slot={slot} unix_timestamp={unix_timestamp}",
        cases.len(),
        cases.len() - 1,
        cases.len() - 1,
    );
}
