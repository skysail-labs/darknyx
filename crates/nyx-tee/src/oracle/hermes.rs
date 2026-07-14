//! Hermes HTTPS client. Talks to `hermes.pyth.network` (or a
//! configurable mirror) and returns parsed price updates ready
//! for the VAA verifier.
//!
//! Endpoint shape (Hermes v2 API):
//!
//! ```text
//! GET https://hermes.pyth.network/v2/updates/price/latest
//!     ?ids[]=<feed_id_hex>
//!     [&ids[]=<another_feed_id>]
//! ```
//!
//! Response:
//!
//! ```json
//! {
//!   "binary": {
//!     "encoding": "hex",
//!     "data": ["010000000001005..."]  ← VAA bytes, hex-encoded
//!   },
//!   "parsed": [
//!     {
//!       "id": "ef0d8b6f...",
//!       "price":     { "price": "12345678", "conf": "100", "expo": -8, "publish_time": 1700000000 },
//!       "ema_price": { "price": "12345555", "conf": "100", "expo": -8, "publish_time": 1700000000 }
//!     }
//!   ]
//! }
//! ```
//!
//! We use `ema_price` as the TWAP — same convention as the
//! on-chain `read_oracle_price` reader (it pulls `ema_price` out of
//! `PriceUpdateV2`).

use anyhow::Result;
use serde::Deserialize;
use std::time::Duration;

/// Default Hermes endpoint. Override via `HermesClient::with_endpoint`
/// if we need to point at hermes-beta.pyth.network or a
/// self-hosted mirror.
pub const DEFAULT_HERMES_ENDPOINT: &str = "https://hermes.pyth.network";

#[derive(Debug, thiserror::Error)]
pub enum HermesError {
    #[error("HTTP request to {url} failed: {source}")]
    Http {
        url: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("Hermes returned HTTP {status} for {url}: {body}")]
    Status {
        url: String,
        status: u16,
        body: String,
    },
    #[error("Hermes response JSON parse failed for {url}: {source}")]
    Json {
        url: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("Hermes returned no parsed price for feed {feed_id}")]
    MissingParsed { feed_id: String },
    #[error("Hermes returned no VAA binary data for feed {feed_id}")]
    MissingVaa { feed_id: String },
    #[error("invalid hex in Hermes VAA binary: {0}")]
    InvalidHex(#[from] hex::FromHexError),
    #[error("Pyth EMA price was non-positive ({0}) — refusing to cache")]
    NonPositivePrice(i64),
}

#[derive(Debug, Clone)]
pub struct HermesPriceUpdate {
    pub feed_id: String,
    /// Raw `AccumulatorUpdateData` (PNAU) bytes from `binary.data[0]` — the
    /// **trusted** price source. The caller (`sync.rs`) verifies the VAA
    /// guardian signatures, extracts the guardian-signed Merkle root, proves
    /// the price message's inclusion under it, and decodes the price from
    /// THIS binary — not from the JSON fields below (C-05 / A-2).
    pub accumulator: Vec<u8>,
    /// EMA price as reported by Hermes's JSON `parsed[]`. Used **only** as a
    /// cross-check against the binary-proven value; never cached directly. A
    /// malicious/buggy Hermes could put a fabricated value here, so it is not
    /// trusted — it exists to catch a JSON-vs-binary split (and our own decode
    /// bugs) loudly.
    pub json_ema_price: u64,
    /// Hermes JSON EMA exponent — cross-check only.
    pub json_exponent: i32,
    /// Hermes JSON EMA publish time (ms) — cross-check only.
    pub json_publish_time_ms: u64,
}

#[derive(Clone)]
pub struct HermesClient {
    endpoint: String,
    http: reqwest::Client,
}

impl HermesClient {
    pub fn new() -> Result<Self, reqwest::Error> {
        Self::with_endpoint(DEFAULT_HERMES_ENDPOINT)
    }

    pub fn with_endpoint(endpoint: &str) -> Result<Self, reqwest::Error> {
        let http = reqwest::Client::builder()
            // Reasonable timeouts. Hermes responds in 10-200 ms typically;
            // 5 s is generous enough for slow network days.
            .timeout(Duration::from_secs(5))
            .user_agent(concat!("nyx-tee/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            http,
        })
    }

    /// Fetch the latest price + VAA for a single feed id (hex).
    pub async fn fetch(&self, feed_id: &str) -> Result<HermesPriceUpdate, HermesError> {
        let url = format!(
            "{}/v2/updates/price/latest?ids[]={}",
            self.endpoint, feed_id
        );

        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|source| HermesError::Http {
                url: url.clone(),
                source,
            })?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(HermesError::Status {
                url: url.clone(),
                status: status.as_u16(),
                body,
            });
        }

        let body = resp.text().await.map_err(|source| HermesError::Http {
            url: url.clone(),
            source,
        })?;
        let parsed: RawResponse =
            serde_json::from_str(&body).map_err(|source| HermesError::Json {
                url: url.clone(),
                source,
            })?;

        // Keep the raw `AccumulatorUpdateData` (PNAU) bytes intact. Hermes
        // returns hex strings in `binary.data[]`; we take the first one
        // (single-feed queries have one). `sync.rs` parses + verifies it: it
        // extracts the VAA, checks the guardian signatures, proves the price
        // message's Merkle inclusion under the guardian-signed root, and
        // decodes the price from the binary. This is the C-05 fix — we no
        // longer trust the JSON `parsed[]` price as the source.
        let accum_hex =
            parsed
                .binary
                .data
                .into_iter()
                .next()
                .ok_or_else(|| HermesError::MissingVaa {
                    feed_id: feed_id.to_string(),
                })?;
        let accumulator = hex::decode(accum_hex)?;

        // The JSON `parsed[]` entry is kept ONLY as a cross-check against the
        // binary-proven value (`sync.rs` rejects a JSON-vs-binary mismatch).
        let raw_entry = parsed
            .parsed
            .into_iter()
            .find(|p| p.id.eq_ignore_ascii_case(feed_id))
            .ok_or_else(|| HermesError::MissingParsed {
                feed_id: feed_id.to_string(),
            })?;

        // Pyth's `price` field is a string-encoded i64 ("Pyth-native" fixed
        // point per `expo`). The EMA shares the same scaling.
        let raw_price: i64 = raw_entry
            .ema_price
            .price
            .parse()
            .map_err(|_| HermesError::Json {
                url: url.clone(),
                source: serde::de::Error::custom("ema_price.price not a valid i64"),
            })?;
        if raw_price <= 0 {
            return Err(HermesError::NonPositivePrice(raw_price));
        }

        Ok(HermesPriceUpdate {
            feed_id: raw_entry.id,
            accumulator,
            json_ema_price: raw_price as u64,
            json_exponent: raw_entry.ema_price.expo,
            // Hermes returns publish_time as seconds; convert to ms.
            json_publish_time_ms: raw_entry.ema_price.publish_time * 1000,
        })
    }
}

// ─────── Wire types (private — only used to deserialize Hermes JSON) ────────

#[derive(Debug, Deserialize)]
struct RawResponse {
    binary: RawBinary,
    parsed: Vec<RawParsedEntry>,
}

#[derive(Debug, Deserialize)]
struct RawBinary {
    #[allow(dead_code)]
    encoding: String,
    data: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawParsedEntry {
    id: String,
    ema_price: RawPrice,
    // We don't currently consume `price` (the spot price) — Pyth's
    // EMA is what the on-chain reader also uses, so we mirror that.
    // Keeping the field absent from the struct = serde ignores it.
}

#[derive(Debug, Deserialize)]
struct RawPrice {
    price: String,
    expo: i32,
    publish_time: u64,
}

// The `AccumulatorUpdateData` (PNAU) wrapper is parsed + Merkle-verified in
// `oracle::accumulator` (owned there so the wire format lives in one place);
// `fetch` above returns the raw bytes untouched.
