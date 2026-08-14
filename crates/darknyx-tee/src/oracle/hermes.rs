//! Hermes HTTPS client. Talks to Pyth's authenticated upgraded Hermes service
//! (or an explicitly configured mirror) and returns parsed price updates ready
//! for the VAA verifier.
//!
//! Endpoint shape (Hermes v2 API):
//!
//! ```text
//! GET https://pyth.dourolabs.app/hermes/v2/updates/price/latest
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
use std::collections::{HashMap, HashSet};
use std::time::Duration;

pub const UPGRADED_HERMES_ENDPOINT: &str = "https://pyth.dourolabs.app/hermes";
/// The authenticated upgraded service is the default for new configurations.
pub const DEFAULT_HERMES_ENDPOINT: &str = UPGRADED_HERMES_ENDPOINT;

#[derive(Debug, thiserror::Error)]
pub enum HermesError {
    #[error("HTTP request to {url} failed: {source}")]
    Http {
        url: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("Hermes returned HTTP {status} for {url}")]
    Status { url: String, status: u16 },
    #[error("Hermes response JSON parse failed for {url}: {source}")]
    Json {
        url: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("Hermes returned no parsed price for feed {feed_id}")]
    MissingParsed { feed_id: String },
    #[error("Hermes returned {actual} binary payloads; expected exactly one batched accumulator")]
    BinaryPayloadCount { actual: usize },
    #[error("Hermes binary encoding {0:?} is unsupported (expected hex)")]
    UnsupportedEncoding(String),
    #[error("Hermes returned duplicate parsed price for feed {feed_id}")]
    DuplicateParsed { feed_id: String },
    #[error("invalid hex in Hermes VAA binary: {0}")]
    InvalidHex(#[from] hex::FromHexError),
    #[error("Pyth EMA price for {feed_id} was non-positive ({price}) — refusing to cache")]
    NonPositivePrice { feed_id: String, price: i64 },
    #[error("no Pyth feed ids supplied")]
    EmptyRequest,
}

#[derive(Debug, Clone)]
pub struct HermesPriceUpdate {
    pub feed_id: String,
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

#[derive(Debug, Clone)]
pub struct HermesBatchUpdate {
    /// One `AccumulatorUpdateData` envelope containing every requested feed.
    pub accumulator: Vec<u8>,
    pub prices: HashMap<String, HermesPriceUpdate>,
}

#[derive(Clone)]
pub struct HermesClient {
    endpoint: String,
    http: reqwest::Client,
    access_token: Option<String>,
}

impl HermesClient {
    pub fn new() -> Result<Self, reqwest::Error> {
        Self::with_endpoint(DEFAULT_HERMES_ENDPOINT)
    }

    pub fn with_endpoint(endpoint: &str) -> Result<Self, reqwest::Error> {
        Self::with_endpoint_and_token(endpoint, None)
    }

    pub fn with_endpoint_and_token(
        endpoint: &str,
        access_token: Option<&str>,
    ) -> Result<Self, reqwest::Error> {
        let http = reqwest::Client::builder()
            // Reasonable timeouts. Hermes responds in 10-200 ms typically;
            // 5 s is generous enough for slow network days.
            .timeout(Duration::from_secs(5))
            .user_agent(concat!("darknyx-tee/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            http,
            access_token: access_token.map(ToOwned::to_owned),
        })
    }

    /// Fetch one accumulator containing every configured feed. This is one
    /// authenticated HTTP request regardless of market count.
    pub async fn fetch_many(&self, feed_ids: &[String]) -> Result<HermesBatchUpdate, HermesError> {
        let request = self.build_request(feed_ids)?;
        let url = request.url().to_string();
        let resp = self
            .http
            .execute(request)
            .await
            .map_err(|source| HermesError::Http {
                url: url.clone(),
                source,
            })?;

        let status = resp.status();
        if !status.is_success() {
            return Err(HermesError::Status {
                url: url.clone(),
                status: status.as_u16(),
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

        self.parse_response(feed_ids, parsed, &url)
    }

    fn build_request(&self, feed_ids: &[String]) -> Result<reqwest::Request, HermesError> {
        if feed_ids.is_empty() {
            return Err(HermesError::EmptyRequest);
        }
        let url = format!("{}/v2/updates/price/latest", self.endpoint);
        let query = feed_ids
            .iter()
            .map(|feed_id| ("ids[]", feed_id.as_str()))
            .collect::<Vec<_>>();

        let mut request = self.http.get(&url).query(&query);
        if let Some(token) = &self.access_token {
            request = request.bearer_auth(token);
        }
        request
            .build()
            .map_err(|source| HermesError::Http { url, source })
    }

    fn parse_response(
        &self,
        feed_ids: &[String],
        parsed: RawResponse,
        url: &str,
    ) -> Result<HermesBatchUpdate, HermesError> {
        // Keep the raw `AccumulatorUpdateData` (PNAU) bytes intact. Hermes
        // returns hex strings in `binary.data[]`; the batched request must
        // return exactly one envelope. `sync.rs` parses + verifies it: it
        // extracts the VAA, checks the guardian signatures, proves the price
        // message's Merkle inclusion under the guardian-signed root, and
        // decodes the price from the binary. This is the C-05 fix — we no
        // longer trust the JSON `parsed[]` price as the source.
        if !parsed.binary.encoding.eq_ignore_ascii_case("hex") {
            return Err(HermesError::UnsupportedEncoding(parsed.binary.encoding));
        }
        if parsed.binary.data.len() != 1 {
            return Err(HermesError::BinaryPayloadCount {
                actual: parsed.binary.data.len(),
            });
        }
        let accum_hex = parsed.binary.data.into_iter().next().unwrap();
        let accumulator = hex::decode(accum_hex)?;

        let requested = feed_ids
            .iter()
            .map(|feed| feed.to_ascii_lowercase())
            .collect::<HashSet<_>>();
        let mut prices = HashMap::with_capacity(feed_ids.len());
        for raw_entry in parsed.parsed {
            let feed_id = raw_entry.id.to_ascii_lowercase();
            if !requested.contains(&feed_id) {
                continue;
            }
            let raw_price: i64 =
                raw_entry
                    .ema_price
                    .price
                    .parse()
                    .map_err(|_| HermesError::Json {
                        url: url.to_string(),
                        source: serde::de::Error::custom("ema_price.price not a valid i64"),
                    })?;
            if raw_price <= 0 {
                return Err(HermesError::NonPositivePrice {
                    feed_id,
                    price: raw_price,
                });
            }
            let update = HermesPriceUpdate {
                feed_id: feed_id.clone(),
                json_ema_price: raw_price as u64,
                json_exponent: raw_entry.ema_price.expo,
                json_publish_time_ms: raw_entry.ema_price.publish_time.saturating_mul(1000),
            };
            if prices.insert(feed_id.clone(), update).is_some() {
                return Err(HermesError::DuplicateParsed { feed_id });
            }
        }
        for feed_id in feed_ids {
            if !prices.contains_key(&feed_id.to_ascii_lowercase()) {
                return Err(HermesError::MissingParsed {
                    feed_id: feed_id.clone(),
                });
            }
        }
        Ok(HermesBatchUpdate {
            accumulator,
            prices,
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
// `fetch_many` above returns the raw bytes untouched.

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::AUTHORIZATION;

    #[test]
    fn default_endpoint_is_the_authenticated_upgraded_service() {
        assert_eq!(DEFAULT_HERMES_ENDPOINT, "https://pyth.dourolabs.app/hermes");
    }

    #[test]
    fn fetch_many_builds_one_authenticated_request_for_all_feeds() {
        let first = "aa".repeat(32);
        let second = "bb".repeat(32);
        let client = HermesClient::with_endpoint_and_token(
            "https://pyth.example/hermes",
            Some("private-token"),
        )
        .unwrap();
        let request = client
            .build_request(&[first.clone(), second.clone()])
            .unwrap();
        let query = request.url().query_pairs().collect::<Vec<_>>();
        assert_eq!(
            query
                .iter()
                .filter(|(name, _)| name.as_ref() == "ids[]")
                .count(),
            2,
            "one request carries both repeated ids[] query parameters"
        );
        assert_eq!(query[0].1, first);
        assert_eq!(query[1].1, second);
        assert_eq!(request.headers()[AUTHORIZATION], "Bearer private-token");

        let body = format!(
            r#"{{
                "binary": {{"encoding":"hex","data":["00"]}},
                "parsed": [
                    {{"id":"{first}","ema_price":{{"price":"100","expo":-8,"publish_time":10}}}},
                    {{"id":"{second}","ema_price":{{"price":"200","expo":-8,"publish_time":11}}}}
                ]
            }}"#
        );
        let parsed = serde_json::from_str(&body).unwrap();
        let update = client
            .parse_response(
                &[first.clone(), second.clone()],
                parsed,
                request.url().as_str(),
            )
            .unwrap();
        assert_eq!(update.accumulator, vec![0]);
        assert_eq!(update.prices.len(), 2);
    }

    #[test]
    fn status_error_never_echoes_bearer_token() {
        let error = HermesError::Status {
            url: "https://pyth.example/hermes/v2/updates/price/latest".into(),
            status: 401,
        };
        let rendered = error.to_string();
        assert!(rendered.contains("401"));
        assert!(!rendered.contains("do-not-log-me"));
    }
}
